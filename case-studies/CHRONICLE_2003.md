# The Year 2003 in Intrusions: A Dated Record

*A TeamStarWolf case study. Published 13 November 2026; every source checked as of that date.*

[All case studies](/case-studies/README.md) · Related: [Notable Incidents](/NOTABLE_INCIDENTS.md), [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [CVE Reference](/CVE_REFERENCE.md), [Supply Chain Security](/SUPPLY_CHAIN_SECURITY.md), [Incident Response](/INCIDENT_RESPONSE_REFERENCE.md), [ICS ATT&CK Atlas](/ICS_ATTACK_ATLAS.md) · Home studies for events summarized here: [The Dot-Com Era: Cyber Events, 1994 to 2003](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) (Slammer, CA-2003-08, Blaster and the Parson case, the National Strategy, California SB 1386, the Ivanov sentence, CAN-SPAM), [Four Books on Cybercrime](/case-studies/CYBERCRIME_FOUR_BOOKS.md) (Operation Firewall, Agobot and Weaknees, Operation Cyberslam), [The Mitnick intrusions](/case-studies/MITNICK_INTRUSIONS.md) (the Lamo record), [Russia-attributed actors](/case-studies/THREAT_ACTORS_RUSSIA.md) (Snake and Turla), [United States actors](/case-studies/THREAT_ACTORS_UNITED_STATES.md) (Equation and Regin) · Series: [The Year 2001 in Intrusions](/case-studies/CHRONICLE_2001.md), [The Year 2002 in Intrusions](/case-studies/CHRONICLE_2002.md), [The Year 2016 in Intrusions](/case-studies/CHRONICLE_2016.md) and the other years in the [case studies index](/case-studies/README.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Threat intelligence analysts, security historians, ICS and open-source defenders and anyone who wants the history behind current threats

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Beginner to intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 65 min (14,839 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want a dated record of the intrusions of 2003, you need the year's CERT advisories, Microsoft bulletins and worms side by side with the GNU and Debian server compromises, Slammer at Davis-Besse, the blackout record, the year's prosecutions and the new spam and breach law, or you want the defender lessons that still apply

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [Part 1: the year as a dated timeline](#part-1-the-year-as-a-dated-timeline), [Part 4: the compromised project servers](#part-4-the-compromised-project-servers)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Notable Incidents](/NOTABLE_INCIDENTS.md), [The Dot-Com Era: Cyber Events, 1994 to 2003](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md), [Supply Chain Security](/SUPPLY_CHAIN_SECURITY.md), [The Year 2002 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2002.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive summary

Anyone who ran a network in 2003 remembers the worms. On Saturday 25 January, slightly before 05:30 UTC, the Slammer worm (also called Sapphire) began infecting Microsoft SQL Server 2000 and MSDE 2000 hosts through their Resolution Service on UDP 1434. Its infected population doubled every 8.5 seconds, it reached more than 90 percent of vulnerable hosts within ten minutes, and it infected at least 75,000 hosts (Confirmed [30]). The fix, MS02-039, had been published six months earlier, on 24 July 2002 (Confirmed [5]). In August Blaster went through the Windows DCOM RPC flaw that MS03-026 had fixed on 16 July, 26 days before CERT/CC's worm advisory (Confirmed [8][1]; the interval is Inferred). Around them came Sobig and its variants, Fizzer, Mimail, Welchia and Swen, and CERT/CC wrote that worm spread had fallen from hours to minutes and that one Sobig variant beat antivirus signatures that were current for its predecessors (Confirmed [2]; Reported [32][33][34]).

The rest of the record is quieter and in some ways more instructive. The server behind the GNU project's primary FTP sites was root compromised, reportedly in March, and CERT/CC announced it only on 13 August (Confirmed [1]). In November an attacker with a sniffed password and a kernel flaw installed rootkits on four Debian project machines; a file integrity checker and kernel crashes gave it away within a day (Confirmed [38]; Inferred for the interval). Slammer took down monitoring computers at the idled Davis-Besse nuclear plant in January, and when the Northeast lost power on 14 August, the US-Canada task force found no evidence that any attacker or worm caused or contributed to the blackout (Confirmed [35][36]).

The crime record runs from a Russian extortionist's sentence in July to a wireless intrusion into a home-improvement chain in October and November that aimed to capture customers' card data (Confirmed [43][50]). Prosecutors arrested the author of one Blaster variant in August and a juvenile behind another in September. In November Microsoft put up a $5 million reward fund, offering $250,000 each for the authors of the original Blaster and of Sobig, for whom no arrests had been made (Confirmed [44][48][15]). The law moved too: CAN-SPAM, FACTA, California's breach-notice law taking effect, HSPD-7, the UK's electronic-communications privacy rules and a UN General Assembly resolution on a culture of cybersecurity (Confirmed [60][61][62][59][63][65]). Microsoft announced monthly patch releases on 9 October and published its first monthly batch on 15 October (Confirmed [14][10]).

The state record of 2003 is almost entirely written later. A 2023 advisory from nine agencies says Russia's FSB began developing the Snake implant, as "Uroburos", in late 2003 (Confirmed [76]). Kaspersky's 2014 and 2015 reports date some Regin timestamps and the start of EQUATIONDRUG to 2003 without naming a state (Confirmed [79][81]). TIME's 2005 reporting dates the start of the Titan Rain intrusions to 2003, on documents and unnamed officials (Reported [84][85]).

2003 has CVE ids in the candidate form CAN-2003-xxxx that the advisories cite (Confirmed [1]). The first CWE List came in 2006 and CAPEC in 2007, and CVSS found its custodian in 2005, so no 2003 record carries a CWE, CAPEC or CVSS id from the time (Confirmed [73][74][75]), and none carries an ATT&CK id (Inferred). Every ATT&CK, CAPEC and D3FEND id in Part 10 is this study's later mapping, apart from the objects ATT&CK itself dates to 2003 (Inferred).

This study is the dated record of the year, built only from sources opened on 12 and 13 November 2026 and checked as of 13 November 2026. Nine parts cover the timeline, the vulnerability record, the worms, the compromised project servers, the grid and the plant, the state record, crime and prosecutions, law and standards, and the defender view. A tenth part maps the record to MITRE frameworks.

### Key facts at a glance

| Field | Value |
|---|---|
| Period | 1 January to 31 December 2003, plus the boundary records that open or close a 2003 event: MS02-039 (24 Jul 2002), the Amato and Jiang conduct (2001 to 2002), the task force's final report (April 2004), the Salcedo and Parson sentences (Dec 2004, Jan 2005), the 2008 Cyberslam indictment, and the later vendor and government reports that date state tools to 2003 |
| CERT/CC output | 28 advisories, CA-2003-01 (ISC DHCPD, 15 Jan) to CA-2003-28 (Windows Workstation Service, 11 Nov); incident notes IN-2003-01 (2 Jul) to IN-2003-04 (1 Oct) (Confirmed [1][2]) |
| Microsoft | 51 bulletins, MS03-001 (22 Jan) to MS03-051 (11 Nov); monthly releases announced 9 Oct, first monthly batch 15 Oct (Confirmed [6][13][14][10]; the count of 51 is Inferred) |
| Worms and mass mailers | Sobig (9 or 10 Jan); Slammer (25 Jan); Fizzer (8 May); Mimail (1 Aug); Blaster (11 Aug) and its B and RPCSDBOT variants; Welchia (18 Aug); Sobig.F (22 Aug); Swen (18 Sep) (Confirmed [30][1][2][15][44][48]; Reported [31][32][33][34]) |
| Exploited in the wild, per CERT | IIS 5.0 WebDAV through ntdll.dll (17 Mar); weak Administrator passwords on SMB shares (11 Mar); DCOM RPC with public exploits (31 Jul); Internet Explorer VU#865940 (1 Oct) (Confirmed [1][2]) |
| Project servers compromised | GNU's primary FTP server (reportedly March; CA-2003-21, 13 Aug); four Debian machines (19 Nov) (Confirmed [1][38]) |
| Energy | Slammer at Davis-Besse (January); the Northeast blackout (14 Aug), with no evidence of malicious cause (Confirmed [35][36]; Reported [37] for the Davis-Besse path) |
| State record | Snake development begins late 2003 (AA23-129A); Regin timestamps back to 2003; EQUATIONDRUG 2003 to 2013; Titan Rain "since 2003"; Iraq war communications attacks (Confirmed [76][77][79][80][81]; Reported [84][85][88]) |
| Prosecutions | Zezev convicted (26 Feb); Racine plea agreement (12 Jun); Jiang plea (10 Jul); Ivanov sentenced (25 Jul); Parson arrested (29 Aug); Lamo charged (9 Sep); Carlson, a juvenile and O'Keefe charged (Sep and Oct); Lowe's indictment (19 Nov); Operation Cyber Sweep (20 Nov); Baas plea (18 Dec) (Confirmed [39] to [55]) |
| Law and policy | National Strategy (Feb); SB 1386 operative (1 Jul); UK PECR in force (11 Dec); FACTA (4 Dec); CAN-SPAM (16 Dec); HSPD-7 (17 Dec); UN A/RES/58/199 (23 Dec) (Confirmed [58][62][63][61][60][59][65]) |
| Standards | RFC 3546 TLS Extensions (Jun); NIST SP 800-42 and SP 800-50 (Oct) (Confirmed [72][67][68]) |
| This study's MITRE binding | 35 ATT&CK Enterprise technique rows, every one a later mapping; 2 ATT&CK for ICS techniques for Davis-Besse; Uroburos (S0022), Regin (S0019), Equation (G0020) and Turla (G0010) bound with their dating caveats; no campaign object; NVD's CWE-119 and CWE-415 plus three study classes; 10 CAPEC entries; D3FEND pairings from the library's data; one Enterprise and one ICS Navigator layer (Part 10) |

### Key findings

- **Patches came first, and it was not enough.** MS02-039 preceded Slammer by six months and MS03-026 preceded Blaster by 26 days (Confirmed [5][8][1]; the intervals are Inferred). CERT/CC recorded hosts that could not stay online long enough to download the Blaster patch (Confirmed [1]).
- **Speed outran signatures.** CERT/CC said worm propagation fell from hours with Code Red in 2001 to minutes with Slammer, and Sobig.E compromised users whose signatures were current for earlier variants (Confirmed [2]). Slammer passed 55 million scans a second after about three minutes (Confirmed [30]).
- **Weak passwords were a worm's front door again.** Thousands of Windows 2000 and XP systems, home broadband users a prime target, fell through null or weak Administrator passwords on SMB shares, and the tools behind it took IRC commands and installed denial-of-service agents (Confirmed [1]).
- **The software archive was a target.** GNU's FTP server and four Debian machines were root compromised; Debian verified its package archives as unaltered, and CERT/CC said no GNU source distributions were believed modified (Confirmed [38][1]).
- **The defender's own tools carried flaws.** CA-2003-13 reported remotely exploitable flaws in the Snort intrusion detection system, and CA-2003-26 reported SSL/TLS parsing flaws in OpenSSL and other implementations (Confirmed [1]).
- **The blackout was not a cyberattack.** The task force's Security Working Group found no evidence that malicious actors or worms caused or contributed to the 14 August outage; the task force said a software failure not linked to malicious activity may have contributed significantly (Confirmed [35][36]).
- **A firewall was bypassed, not broken.** In Poulsen's account, Slammer reached the Davis-Besse plant network through a contractor link that went around a firewall that did block Slammer's port (Reported [37]).
- **The state record is written in hindsight.** The 2003 dates for Snake, Regin and EQUATIONDRUG come from reports published in 2014, 2015 and 2023 (Confirmed [76][79][81]).

### Top recommendations

1. **Measure the gap between fix and worm.** Six months for Slammer and 26 days for Blaster (Confirmed [5][8][1]; Inferred for the intervals). Track time to patch for exposed services against those numbers.
2. **Filter at the border, and do not stop there.** CERT/CC said UDP 1434 filtering only limits damage from hosts already infected, and VU#568148 warned that perimeter blocks leave attackers inside able to exploit the RPC flaw (Confirmed [1][4]).
3. **Turn on host firewalls before the patch.** MS03-026 and CA-2003-20 named Internet Connection Firewall, which blocks inbound RPC by default on XP and Server 2003, as a step before patching (Confirmed [8][1]).
4. **Remove null and weak administrator passwords.** CA-2003-08's compromises needed nothing more (Confirmed [1]).
5. **Verify what you download.** CERT/CC told GNU users that timestamps and file sizes cannot detect tampering, and the FSF published PGP-signed MD5 lists (Confirmed [1]).
6. **Watch file integrity on the servers that build and ship code.** Debian's intrusion was found through kernel crashes and AIDE, a file integrity checker (Confirmed [38]).
7. **Map every link into a control network.** The Davis-Besse path in Poulsen's account ran through a contractor connection, not the firewall (Reported [37]); the task force named SCADA links to other systems among the weaknesses it observed (Confirmed [36]).
8. **Treat an account that exceeds its access as an incident.** The Acxiom case started with a customer's systems administrator and cost Acxiom more than $5.8 million (Confirmed [55]).

## Scope and method

This study covers intrusions, vulnerabilities, malware, prosecutions, regulation, standards and policy dated to 2003, plus the later records that open, close or explain a 2003 event. It follows the method of the [case studies collection](/case-studies/README.md): primary sources first, every claim graded, numbers as the source states them. Sources were opened on 12 November 2026; some were opened again, and others opened for the first time, on 13 November 2026.

| Grade | Meaning in this study |
|---|---|
| Confirmed | The primary record was opened and states the fact: a CERT/CC advisory, incident note or vulnerability note as SEI and CERT publish it, a vendor bulletin, release or research report stated as that vendor's own finding, a CVE or NVD record, a statute or statutory instrument, a Justice Department, US Attorney or Secret Service release, a government report, strategy or directive, a UN, ITU, Council of Europe, NIST, RFC Editor or MITRE record, a live ATT&CK page, or the Debian project's own report |
| Reported | Only a secondary source supports the fact, or the source gives its own assessment without the evidence: TIME on Titan Rain, the New York Times on the Iraq war operations, Poulsen on Davis-Besse, the impacts CAIDA relays without measuring, Kaspersky's attribution judgements, and the F-Secure dates noted below. The source is named in the text |
| Demonstrated | A check this study ran itself and saw the result: id, name, tactic and page checks in the library's data files and `mitre/` page tree |
| Inferred | The study's own reasoning, labelled where it appears. Every ATT&CK Enterprise, ATT&CK for ICS, CAPEC and D3FEND id bound to a 2003 event is Inferred as to the binding, and so is every CWE that NVD does not list |

F-Secure's virus descriptions are a vendor record; the dates and behaviors this study takes from them for Sobig, Fizzer, Welchia and Swen rest on F-Secure's pages alone and stay Reported [31][32][33][34].

Limits a reader should know:

- **No contemporaneous ATT&CK, CWE, CAPEC or CVSS.** MITRE began categorizing weaknesses with the CVE List in 1999, revised that work in 2005 under NIST SAMATE, and first released the CWE List in 2006; CAPEC was established by DHS and first released in 2007; FIRST became custodian of CVSS on 14 April 2005, so CVSS scores on 2003 CVE records are retrospective (Confirmed [73][74][75]; Inferred for the reading). Years before 2015 have no contemporaneous ATT&CK mapping in this series; where ATT&CK itself dates an object to 2003, Part 10 says so.
- **The CERT text.** SEI's compilations of the 2003 CERT advisories and incident notes are the texts for every CA-2003 and IN-2003 item cited here [1][2]. The advisories print exploit ports, file names and hard-coded addresses; none is reproduced here beyond the service and listening port numbers the advisories name.
- **A defect in the advisory compilation.** In SEI's compilation the CA-2003-25 (Sendmail) heading carries the CA-2003-26 SSL/TLS text and its 1 October date, so this study cites no CA-2003-25 date or content (Confirmed [1]).
- **The 28 advisories are a curated set.** They are the cases CERT chose to publish, weighted to widely deployed software, not a census of the year's intrusions (Inferred).
- **What was not checked.** No primary was opened for: NRC Information Notice 2003-14 on Davis-Besse (the NRC returned an error) and the NERC report the task force relays; the FTC's 2003 Guess settlement; the Gentoo rsync server compromise and the Linux kernel CVS back-door attempt (both late 2003); the FSF's own GNU announcement and the Savannah compromise; the Data Processors International card breach (February); the Valve source-code theft (October); the CSX signalling disruption blamed on Sobig (August); Slammer impacts at named banks, airlines and emergency services; Welchia impacts at named organizations; the creation of DHS's National Cyber Security Division and US-CERT; GAO-04-354; the 2003 Wall Street Journal article on Storm Cloud; the Reuters reporting on later Chinese intrusions; Wi-Fi Protected Access; the OWASP Top Ten of 2003; the HIPAA Security Rule; and whether any 2003 CVE is in CISA's Known Exploited Vulnerabilities catalog. They are left out. Their absence here is not evidence that nothing happened.

## Part 1: the year as a dated timeline

One row per event or report. The date is the event date where the source gives one, otherwise the publication date.

| Date | Event | Thread | Sector | Grade | Sources |
|---|---|---|---|---|---|
| 2001 to 2003 (frame) | Kaspersky: EQUATIONLASER in use around 2001 to 2003, followed by EQUATIONDRUG from 2003 | Espionage | Unknown | Reported | [81] |
| 2001-02-14 to 2002-12-20 (frame) | Juju Jiang's keylogging software on Kinko's terminals in Manhattan (plea 10 Jul 2003) | Crime | Public kiosks, consumers | Confirmed | [42] |
| 2001-11-05 to 14 (frame) | Dino Amato mails a "ZIP-42" archive to NASA Glenn's mail server, slowing or stopping mail (charged 13 Feb 2003) | Insider | Government, space | Confirmed | [40] |
| 2002-07-24 | MS02-039 published, credit David Litchfield of NGS Software; it fixes the flaw Slammer later used. Home: [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) | Vulnerability | Databases | Confirmed | [5] |
| 2003-01-09 | F-Secure: first Sobig variant found in the wild, spreading by email and network shares | Worm | Cross-sector | Reported | [31] |
| 2003-01-10 | Microsoft: first Sobig variant detected; Sobig.B and Sobig.C later spoofed Microsoft e-mail addresses | Worm | Cross-sector | Confirmed | [15] |
| 2003-01-15 | CA-2003-01: ISC DHCPD minires overflows (CAN-2003-0026), found by ISC's own audit; no known exploits | Vulnerability | Network infrastructure | Confirmed | [1] |
| 2003-01-22 | MS03-001, Windows Locator Service; CA-2003-02, CVS double free | Vulnerability | Cross-sector | Confirmed | [6][1] |
| 2003-01-23 | CA-2003-03 on the Windows Locator Service | Vulnerability | Cross-sector | Confirmed | [6][1] |
| 2003-01-25 | Slammer (Sapphire) begins slightly before 05:30 UTC; CA-2003-04 the same day. Home: [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) | Worm | Databases, internet | Confirmed | [30][1] |
| 2003-01 | Slammer takes down monitoring computers at the idled Davis-Besse nuclear plant | Industrial | Energy (nuclear) | Confirmed; Reported (the path) | [35][36][37] |
| 2003-01 | Microsoft updates MS02-039 to recommend MS02-061, in an update dated 31 Jan | Vulnerability | Databases | Confirmed | [3][5] |
| 2003-01-28 | Council of Europe ETS 189, the Additional Protocol to the Convention on Cybercrime, done at Strasbourg | Law | Cross-sector | Confirmed | [64] |
| 2003-02 | The National Strategy to Secure Cyberspace | Policy | Cross-sector | Confirmed | [58] |
| 2003-02-13 | Information filed against Amato over the NASA mail server | Insider | Government, space | Confirmed | [40] |
| 2003-02-19 | CA-2003-05: Oracle | Vulnerability | Databases | Confirmed | [1] |
| 2003-02-21 | CA-2003-06: SIP implementations | Vulnerability | Telephony | Confirmed | [1] |
| 2003-02-26 | Oleg Zezev convicted of hacking Bloomberg L.P. and attempting a $200,000 extortion | Crime | Financial data | Confirmed | [39] |
| 2003-03 | Root compromise of the server behind ftp.gnu.org and alpha.gnu.org, as later reported | Supply chain | Open source | Confirmed | [1] |
| 2003-03 | John William Racine II takes over the Aljazeera.net domain account with a forged ID and form | Crime | Media | Confirmed | [41] |
| 2003-03 | NYT (2009): digital attacks on Iraq's telephone networks in the war's first hours; a planned attack on Iraq's banking system never approved | State | Telecommunications, finance | Reported | [88] |
| 2003-03-03 | CA-2003-07: remote overflow in Sendmail (CVE-2002-1337) | Vulnerability | Mail | Confirmed | [1][25] |
| 2003-03-11 | CA-2003-08: Windows systems compromised through null or weak Administrator passwords. Home: [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) | Botnet | Consumers, cross-sector | Confirmed | [1] |
| 2003-03-17 | MS03-007 and CA-2003-09: ntdll.dll overflow actively exploited through WebDAV on IIS 5.0 (CVE-2003-0109) | Exploitation | Web hosting | Confirmed | [7][1][20] |
| 2003-03-19 | CA-2003-10: Sun RPC XDR | Vulnerability | Cross-sector | Confirmed | [1] |
| 2003-03-26 | CA-2003-11: Lotus Notes and Domino; Racine admits the hijack to the FBI | Vulnerability; Crime | Cross-sector; Media | Confirmed | [1][41] |
| 2003-03-29 | CA-2003-12: a second Sendmail overflow (CVE-2003-0161), found by Michal Zalewski | Vulnerability | Mail | Confirmed | [1][26] |
| 2003-04-17 | CA-2003-13: two remotely exploitable flaws in Snort preprocessors | Vulnerability | Security tools | Confirmed | [1] |
| 2003-05-05 | CVE-2003-0209, the Snort stream4 flaw, carries this published date in NVD | Vulnerability | Security tools | Confirmed | [23] |
| 2003-05-08 | F-Secure: the Fizzer email and P2P worm appears; it kills anti-virus tasks and updates itself | Worm | Consumers | Reported | [32] |
| 2003-05-28 | Windows Server 2003 support lifecycle starts (Itanium 19 Jun) | Industry | Technology | Confirmed | [17] |
| 2003-06 | RFC 3546, TLS Extensions, defines Server Name Indication | Standards | Internet | Confirmed | [72] |
| 2003-06-12 | Racine agrees to plead guilty | Crime | Media | Confirmed | [41] |
| 2003-07 | Secret Service Operation Firewall begins. Home: [Four Books on Cybercrime](/case-studies/CYBERCRIME_FOUR_BOOKS.md) | Crime | Payments | Confirmed | [57] |
| 2003-07-01 | California SB 1386 operative; Zezev sentenced to 51 months | Regulation; Crime | Cross-sector; Financial data | Confirmed | [62][39] |
| 2003-07-02 | IN-2003-01: worm propagation down to minutes; Sobig.E beats current signatures | Worm | Cross-sector | Confirmed | [2] |
| 2003-07-10 | Jiang pleads guilty (SDNY) | Crime | Public kiosks | Confirmed | [42] |
| 2003-07-14 | CA-2003-14: Windows HTML conversion | Vulnerability | Cross-sector | Confirmed | [1] |
| 2003-07-16 | MS03-026, DCOM RPC overrun, credit The Last Stage of Delirium Research Group; CA-2003-15 on Cisco IOS blocked interfaces | Vulnerability | Cross-sector; Network infrastructure | Confirmed | [8][1][27] |
| 2003-07-17 | CA-2003-16 on the Microsoft RPC flaw | Vulnerability | Cross-sector | Confirmed | [1] |
| 2003-07-18 | CA-2003-17: an exploit for the Cisco IOS flaw posted publicly | Exploitation | Network infrastructure | Confirmed | [1] |
| 2003-07-25 | Alexey Ivanov sentenced to 48 months; CA-2003-18, DirectX MIDI. Home: [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) | Crime; Vulnerability | E-commerce, banking | Confirmed | [43][1] |
| 2003-07-31 | CA-2003-19: widespread scanning and exploitation of the RPC flaw | Exploitation | Cross-sector | Confirmed | [1] |
| 2003-08-01 | CERT/CC begins receiving W32/Mimail reports; IN-2003-02 on 2 Aug | Worm | Cross-sector | Confirmed | [2] |
| 2003-08 | Daniel Baas charged over the Acxiom data theft | Crime | Data services | Confirmed | [55] |
| 2003-08-11 | CA-2003-20: W32/Blaster. Home: [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) | Worm | Cross-sector | Confirmed | [1] |
| 2003-08-12 | Parson releases his "teekids" Blaster variant | Worm | Cross-sector | Confirmed | [45] |
| 2003-08-13 | CA-2003-21 on the GNU FTP server compromise | Supply chain | Open source | Confirmed | [1] |
| 2003-08-14 | The Northeast blackout, a few minutes after 16:00 EDT | Industrial | Energy | Confirmed | [36] |
| 2003-08-18 | F-Secure: Welchia (Nachi) first reported; CVE-2003-0352 carries this published date in NVD | Worm | Cross-sector | Reported; Confirmed | [33][21] |
| 2003-08-22 | IN-2003-03: W32/Sobig.F | Worm | Cross-sector | Confirmed | [2] |
| 2003-08-26 | CA-2003-22: multiple Internet Explorer flaws (MS03-032) | Vulnerability | Cross-sector | Confirmed | [1] |
| 2003-08-29 | Parson arrested; Microsoft issues a statement | Crime | Technology | Confirmed | [44][16] |
| 2003-09 | TIME: Titan Rain first seen in a Lockheed Martin break-in | Espionage | Defense industry | Reported | [84] |
| 2003-09 | Parson indicted | Crime | Technology | Confirmed | [45] |
| 2003-09-09 | Adrian Lamo charged in SDNY over the 2002 New York Times intrusion. Home: [the Mitnick intrusions study](/case-studies/MITNICK_INTRUSIONS.md) | Crime | Media | Confirmed | [46] |
| 2003-09-10 | MS03-039 and CA-2003-23: three more RPCSS flaws; MS03-026 revised to v2.0; Sobig.F's programmed stop date | Vulnerability; Worm | Cross-sector | Confirmed | [9][8][1][2] |
| 2003-09-16 | CA-2003-24: OpenSSH buffer management | Vulnerability | Cross-sector | Confirmed | [1][29] |
| 2003-09-18 | F-Secure: Swen appears; UK PECR made and laid | Worm; Law | Consumers; Communications | Reported; Confirmed | [34][63] |
| 2003-09-25 | Allan Eric Carlson indicted (unsealed 7 Oct) | Crime | Media, sports | Confirmed | [47] |
| 2003-09-26 | A juvenile arrested for the RPCSDBOT Blaster variant | Crime | Technology | Confirmed | [48] |
| 2003-09-29 | Brett Edward O'Keefe indicted over access to NASA, Army, Navy, DOE and NIH computers | Crime | Government | Confirmed | [49] |
| 2003-10 | Weaknees halted by commissioned DDoS; NIST SP 800-42 and SP 800-50; the Lowe's wireless intrusion begins | Crime; Standards | Retail; Government | Confirmed | [56][67][68][50] |
| 2003-10-01 | CA-2003-26 (SSL/TLS ASN.1); IN-2003-04 (IE VU#865940 exploited); Operation Cyber Sweep begins | Vulnerability; Exploitation; Crime | Cross-sector | Confirmed | [1][2][53] |
| 2003-10-03 | MS03-040, Internet Explorer | Vulnerability | Cross-sector | Confirmed | [10] |
| 2003-10-09 | Microsoft announces monthly patch releases | Industry | Technology | Confirmed | [14] |
| 2003-10-15 | MS03-041 to MS03-045 published together, the first monthly batch | Industry | Technology | Confirmed | [10][11] |
| 2003-10-16 | CA-2003-27: Windows Messenger Service and Exchange | Vulnerability | Cross-sector | Confirmed | [1][11] |
| 2003-11 | The task force's Security Working Group issues its interim findings | Industrial | Energy | Confirmed | [36] |
| 2003-11-05 | Microsoft's Anti-Virus Reward Program, $5 million | Industry | Technology | Confirmed | [15] |
| 2003-11-09 | The Lowe's intrusion ends | Crime | Retail | Confirmed | [50] |
| 2003-11-11 | MS03-049 and CA-2003-28: Workstation Service; MS03-051, the year's last bulletin | Vulnerability | Cross-sector | Confirmed | [12][1][13] |
| 2003-11-17 | CVE-2003-0545, the OpenSSL ASN.1 double free, carries this published date in NVD | Vulnerability | Cross-sector | Confirmed | [24] |
| 2003-11-19 | Debian project machines compromised from 17:00 UTC; Salcedo, Botbyl and Timmins indicted | Supply chain; Crime | Open source; Retail | Confirmed | [38][50] |
| 2003-11-20 | Operation Cyber Sweep announced, with Walter Wiggs's plea agreement (filed 19 Nov) | Crime | Government, social services | Confirmed | [53][52] |
| 2003-11-21 | Debian announces the compromise (10:45 UTC); DOJ and Commerce statement on spam legislation | Supply chain; Policy | Open source; Cross-sector | Confirmed | [38][54] |
| 2003-11-28 | Linux 2.4.23 released with the do_brk() fix | Vulnerability | Open source | Confirmed | [38] |
| 2003-12-02 | Debian's investigation report | Supply chain | Open source | Confirmed | [38] |
| 2003-12-04 | FACTA approved (Pub. L. 108-159) | Law | Financial services | Confirmed | [61] |
| 2003-12-11 | UK PECR in force | Law | Communications | Confirmed | [63] |
| 2003-12-12 | WSIS Geneva Declaration of Principles | Policy | International | Confirmed | [66] |
| 2003-12-16 | CAN-SPAM approved (Pub. L. 108-187). Home: [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) | Law | Cross-sector | Confirmed | [60] |
| 2003-12-17 | HSPD-7 | Policy | Critical infrastructure | Confirmed | [59] |
| 2003-12-18 | Baas pleads guilty | Crime | Data services | Confirmed | [55] |
| 2003-12-23 | UN General Assembly adopts A/RES/58/199 | Policy | International | Confirmed | [65] |
| Late 2003 | AA23-129A: the FSB begins developing Snake as "Uroburos" | Espionage | Government | Confirmed | [76][77] |
| 2003 | Kaspersky: some Regin timestamps date back to 2003; EQUATIONDRUG developed from 2003 | Espionage | Unknown | Confirmed | [79][80][81] |
| 2003 | Kaspersky and King's College London: the Storm Cloud story leaked in a 2003 Wall Street Journal article | Espionage | Government | Reported | [83] |
| Since 2003 | TIME: Titan Rain compromises Redstone Arsenal, NASA and the World Bank | Espionage | Government, defense | Reported | [85][87] |
| 2004-01 (boundary) | NIST SP 800-61, Computer Security Incident Handling Guide | Standards | Government | Confirmed | [69] |
| 2004-02 (boundary) | FIPS 199 | Standards | Government | Confirmed | [70] |
| Early 2004 (boundary) | AA23-129A: initial Snake versions appear completed, operations shortly after | Espionage | Government | Confirmed | [76] |
| 2004-03 (boundary) | TIME: Carpenter's first Titan Rain discoveries | Espionage | Government | Reported | [86] |
| 2004-04 (boundary) | US-Canada task force final report | Industrial | Energy | Confirmed | [35][36] |
| 2004-10 (boundary) | Operation Firewall arrests announced | Crime | Payments | Confirmed | [57] |
| 2004-11-01 (boundary) | TIME: scans from southern China hit Fort Huachuca, DISA and other sites | Espionage | Military | Reported | [87] |
| 2004-12-15 (boundary) | Salcedo sentenced to 108 months | Crime | Retail | Confirmed | [51] |
| 2005-01-28 (boundary) | Parson sentenced to 18 months | Crime | Technology | Confirmed | [45] |
| 2008-10-02 (boundary) | Operation Cyberslam indictment release names the 2003 Weaknees attacks | Crime | Retail | Confirmed | [56] |
| 2014-11-24 (boundary) | Kaspersky publishes its Regin report | Espionage | Telecommunications | Confirmed | [79] |
| 2015-02 (boundary) | Kaspersky's Equation Q&A, version 1.5 | Espionage | Unknown | Confirmed | [81] |
| 2023-05-09 (boundary) | AA23-129A attributes Snake to FSB Center 16 | Espionage | Government | Confirmed | [76] |

## Part 2: the vulnerability record

### The 28 advisories

CERT/CC published 28 advisories in 2003, CA-2003-01 on 15 January to CA-2003-28 on 11 November (Confirmed [1]). Grouped by topic (the grouping is this study's; the texts are SEI's compilation) (Confirmed [1]; grouping Inferred):

- **Worms and exploitation in the wild.** CA-2003-04 (25 Jan) the MS-SQL Server worm; CA-2003-08 (11 Mar) weak Administrator passwords; CA-2003-09 (17 Mar) the IIS 5.0 WebDAV overflow, actively exploited; CA-2003-19 (31 Jul) exploitation of the RPC flaw; CA-2003-20 (11 Aug) Blaster (Part 3).
- **Microsoft platforms.** CA-2003-03 (23 Jan) Locator Service; CA-2003-14 (14 Jul) HTML conversion; CA-2003-16 (17 Jul) and CA-2003-23 (10 Sep) RPC and RPCSS; CA-2003-18 (25 Jul) DirectX MIDI; CA-2003-22 (26 Aug) Internet Explorer; CA-2003-27 (16 Oct) Windows Messenger Service and Exchange; CA-2003-28 (11 Nov) Workstation Service (Confirmed [1]).
- **Mail.** CA-2003-07 (3 Mar), a remote overflow in Sendmail, now CVE-2002-1337, the crackaddr overflow in Sendmail 5.79 to 8.12.7; CA-2003-12 (29 Mar), a separate Sendmail stack overflow from a char-to-signed-int conversion in address token length checks, found by Michal Zalewski, now CVE-2003-0161 in prescan() before 8.12.9 (Confirmed [1][25][26]). CA-2003-11 (26 Mar) covered Lotus Notes and Domino (Confirmed [1]).
- **Network infrastructure.** CA-2003-01 (15 Jan) ISC DHCPD minires overflows (CAN-2003-0026), found by ISC's own source audit, with no exploits known to CERT; CA-2003-06 (21 Feb) SIP implementations; CA-2003-10 (19 Mar) Sun RPC XDR; CA-2003-15 (16 Jul) and CA-2003-17 (18 Jul) Cisco IOS (Confirmed [1]).
- **Databases and applications.** CA-2003-02 (22 Jan) a CVS double free; CA-2003-05 (19 Feb) Oracle (Confirmed [1]).
- **Security software and cryptography.** CA-2003-13 (17 Apr) Snort; CA-2003-24 (16 Sep) OpenSSH; CA-2003-26 (1 Oct) SSL/TLS (Confirmed [1]).

### Cisco IOS: an exploit in two days

CA-2003-15 (16 Jul) announced a denial-of-service flaw in how Cisco IOS handles certain IPv4 packets that block an interface (VU#411332, cisco-sa-20030717-blocked). Two days later CA-2003-17 reported that an exploit had been posted publicly and that CERT expected intruders to use it to cause outages (Confirmed [1]). The CVE record, CVE-2003-0567, covers IOS 11.x and 12.0 through 12.2 (Confirmed [27]).

### The defender's own tools

CA-2003-13 (17 Apr) reported two remotely exploitable flaws in the preprocessors of the Snort intrusion detection system: a stream4 heap overflow (CAN-2003-0209, found by CORE Security) and an RPC preprocessor overflow (CAN-2003-0033). Either allows code execution as the user running Snort, typically root (Confirmed [1]). NVD describes CVE-2003-0209 as an integer overflow that enables a heap-based buffer overflow and lists NVD-CWE-Other (Confirmed [23]). CA-2003-24 (16 Sep) reported buffer management errors in OpenSSH before 3.7.1 that could corrupt heap memory and noted incident reports that might be related; the CVE record, CVE-2003-0693, says before 3.7 (Confirmed [1][29]). CA-2003-26 (1 Oct) reported multiple SSL/TLS implementation flaws, mainly in ASN.1 parsing, found with the UK NISCC test suite, in OpenSSL before 0.9.7c and 0.9.6k and in other implementations; the worst case was code execution and the common impact denial of service, and CERT advised servers to ignore unsolicited client certificate messages (Confirmed [1]). NVD maps one of those flaws, CVE-2003-0545, an OpenSSL 0.9.7 ASN.1 double free reachable through a client certificate, to CWE-415 (Confirmed [24]).

### Microsoft's year

Microsoft's 2003 bulletins run from MS03-001 (22 Jan, Locator Service) to MS03-051 (11 Nov); a request for MS03-052 returns no bulletin, so the series holds 51 (Confirmed [6][13]; Inferred for the count). Bulletins cited here:

- **MS03-007 (17 Mar).** An unchecked buffer in ntdll.dll, actively exploited through WebDAV on IIS 5.0 to run code as Local System; CERT's CA-2003-09 came the same day (Confirmed [7][1]). NVD lists CVE-2003-0109 with NVD-CWE-Other, published 31 Mar (Confirmed [20]).
- **MS03-026 (16 Jul).** A buffer overrun in the DCOM RPC interface (CAN-2003-0352) in Windows NT 4.0, 2000, XP and Server 2003, rated Critical and credited to The Last Stage of Delirium Research Group (Confirmed [8]). Its workarounds were to block UDP 135, 137, 138 and 445 and TCP 135, 139, 445 and 593, disable COM Internet Services and RPC over HTTP, use a personal firewall such as Internet Connection Firewall, use IPsec filters, or disable DCOM (Confirmed [8]). It was revised through version 2.0 on 10 September, adding ports, a scanning tool (KB 827363) and supersedence by MS03-039 (Confirmed [8]).
- **MS03-039 (10 Sep).** Three new RPCSS flaws, two remotely exploitable buffer overruns that run code as Local System and one denial of service; CA-2003-23 came the same day (Confirmed [9][1]). CVE-2003-0605, an RPC DCOM denial of service and epmapper pipe hijack on Windows 2000 SP3 and SP4, is referenced by CA-2003-19 and CA-2003-23 (Confirmed [28]).
- **MS03-043 (15 Oct).** A buffer overrun in the Messenger Service (CVE-2003-0717); CA-2003-27 followed on 16 Oct and called it the most serious of the Windows and Exchange flaws it covered, allowing unauthenticated remote code execution (Confirmed [11][1]).
- **MS03-049 (11 Nov).** A buffer overrun in the Workstation Service (CVE-2003-0812), with CA-2003-28 the same day, citing eEye's advisory AD20031111 (Confirmed [12][1]).

**The monthly cycle.** On 9 October Steve Ballmer told Microsoft's Worldwide Partner Conference that Microsoft would move to monthly patch releases, and SUS 2.0 was planned for the first half of 2004 (Confirmed [14]). MS03-041, MS03-042, MS03-043, MS03-044 and MS03-045 were all published on 15 October; MS03-040 had been published on 3 October (Confirmed [10]). The monthly schedule that Windows administrators still plan around starts here (Inferred).

**Internet Explorer.** CA-2003-22 (26 Aug) covered multiple Internet Explorer flaws fixed in MS03-032; a note of 4 October says MS03-032 did not fully resolve VU#865940 and MS03-040 supersedes it (Confirmed [1]). IN-2003-04 reported active exploitation of that flaw (Part 3).

### The CVE record

The advisories and bulletins of 2003 cite CVE candidates in the CAN- form (Confirmed [1][8]). NVD now lists CWE-119 for CVE-2002-0649 (Slammer) and CWE-415 for CVE-2003-0545 (OpenSSL); CVE-2003-0352 (Blaster), CVE-2003-0109 (WebDAV), CVE-2003-0209 (Snort), CVE-2003-0161 (Sendmail), CVE-2003-0812 (Workstation) and CVE-2003-0528 (RPCSS) carry NVD-CWE-Other (Confirmed [18][19][24][21][20][23][9]). NVD therefore names a specific weakness for only two of the eight 2003-era CVEs this study checked (Inferred from [18][24]). NVD's CVSS v2 scores on these records, 7.5 for CVE-2002-0649 and CVE-2003-0352 and 10.0 for CVE-2003-0528, were assigned after FIRST took custody of CVSS in 2005 (Confirmed [18][21][9][75]; Inferred for the timing).

## Part 3: the worm year

### Slammer (summary)

The [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) is the home for Slammer (Demonstrated [97]). CERT's CA-2003-04 (25 Jan, revised 27 Jan) calls it the MS-SQL Server worm, also SQLSlammer, W32.Slammer and Sapphire. It exploits VU#484891 (CAN-2002-0649), a stack buffer overflow in the SQL Server 2000 and MSDE 2000 Resolution Service, by sending 376-byte UDP packets to random addresses on port 1434, and it carries no payload beyond scanning; its traffic alone degraded networks (Confirmed [1]). CAIDA's measurements: infections began slightly before 05:30 UTC, the population doubled every 8.5 seconds, more than 90 percent of vulnerable hosts were infected within ten minutes, at least 75,000 hosts were infected, and the full scan rate passed 55 million scans a second after about three minutes, two orders of magnitude faster than Code Red (Confirmed [30]). The same paper relays canceled airline flights, interference with elections and ATM failures; those impacts are relayed, not measured (Reported [30]). The fix, MS02-039, was posted on 24 July 2002 and credited to David Litchfield of NGS Software (Confirmed [5]). CA-2003-04 said ingress and egress filtering of UDP 1434 only limits damage from systems already infected and does not prevent initial infection (Confirmed [1]).

### Weak passwords and bots (summary)

CA-2003-08 (11 Mar) reported thousands of Windows 2000 and XP systems compromised through null or weak Administrator passwords on SMB shares (445/tcp), with home broadband users a prime target. The tools named, W32/Deloder, GT-bot, sdbot and W32/Slackor, scan within the same /16, open back doors, connect to IRC for commands and install denial-of-service tools (Confirmed [1]). The [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) is the home (Demonstrated [97]).

### Blaster, its variants and Welchia

**The flaw and the exploits.** CA-2003-16 (17 Jul) followed MS03-026, and on 31 July CA-2003-19 reported widespread scanning and exploitation of the RPC flaw (VU#568148) on TCP 135, with multiple public exploits that create a privileged back-door command shell, some listening on TCP 4444. It also tracked a separate RPC denial-of-service flaw, VU#326746 (Confirmed [1]).

**Blaster.** CA-2003-20 (11 Aug) reported W32/Blaster exploiting VU#568148. It retrieves its executable from the host that compromised it, scans for more hosts, persists through a Run registry value, and, in CERT's lab testing, launches a TCP SYN flood against windowsupdate.com (Confirmed [1]). The task force dates Blaster's first notice to 11 August (Confirmed [35]). CERT's recovery guidance was to disconnect the host, remove the registry value and files, then disable DCOM or block TCP 135 with Internet Connection Firewall or another host filter before reconnecting to patch; some hosts could not stay connected long enough to download the patch (Confirmed [1]). The [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) is the home (Demonstrated [97]).

**The "teekids" variant.** Jeffrey Lee Parson released his variant on 12 August, seeded it from about fifty previously hijacked computers and added a remote-access mechanism (Confirmed [45]). The arrest release of 29 August says the variant (W32/Lovesan.worm.b) infected at least 7,000 computers and attacked windowsupdate.com; the government later calculated more than 48,000 infections. He was indicted in September 2003 and sentenced on 28 January 2005 to 18 months (Confirmed [44][45]). Microsoft issued a statement on the arrest the same day (Confirmed [16]).

**The RPCSDBOT variant.** A juvenile was arrested in the Western District of Washington, announced on 26 September, for releasing the RPCSDBOT variant of Blaster, which directed denial-of-service attacks against Microsoft; it was the second arrest in the Blaster investigation (Confirmed [48]).

**Welchia.** F-Secure says Welchia (Nachi) was first reported on 18 August, spreads through the RPC hole Blaster used and the MS03-007 WebDAV flaw, and was built to stop working in 2004 (Reported [33]). The CVE-2003-0352 record names both Blaster and Nachi/Welchia as exploiting the DCOM RPC flaw (Confirmed [21][22]).

**The reward.** On 5 November Microsoft announced its Anti-Virus Reward Program with $5 million in initial funding and $250,000 rewards for the authors of MSBlast.A and Sobig. Two arrests had been made, for the B and C variants of MSBlast; none for Sobig (Confirmed [15]).

### The mass mailers

- **Sobig.** F-Secure records the first Sobig variant in the wild on 9 January, spreading by email and network shares (Reported [31]); Microsoft says it was detected on 10 January and that Sobig.B and Sobig.C spoofed Microsoft e-mail addresses (Confirmed [15]).
- **Sobig.E and the speed problem.** IN-2003-01 (2 Jul) says virus spread had sped up from weeks to hours (BugBear and the Sobig variants), faster than signature updates, and that Sobig.E compromised users whose signatures were current for earlier variants (Confirmed [2]).
- **Fizzer.** F-Secure says Fizzer, an email and P2P worm that kills anti-virus tasks and updates itself, appeared on 8 May (Reported [32]).
- **Mimail.** IN-2003-02 (2 Aug): reports rose from Friday 1 August of a mass mailer sent as a fake administrator account-expiry notice; an MHTML file inside a zip installs the mailer when viewed on a vulnerable system (Confirmed [2]).
- **Sobig.F.** IN-2003-03 (22 Aug): the worm spreads through .pif attachments, adds a Run registry key and mails itself with its own SMTP engine. From 22 August it was scheduled to contact 20 hard-coded hosts on UDP 8998 on Fridays and Sundays from 19:00 to 22:00 UTC, which CERT believed would deliver further code, and it was programmed to stop on 10 September (Confirmed [2]).
- **Swen.** F-Secure says Swen appeared on 18 September, likely by the author of Gibe, and that UPX-packed variants found on 9 October replaced its Microsoft references with Tiscali (Reported [34]).

### Exploitation through the browser

IN-2003-04 (1 Oct, revised 4 Oct) reported attackers exploiting Internet Explorer VU#865940, an HTA referenced from an OBJECT element, to install denial-of-service tools, read registry data, dial pay-per-minute numbers and, in the attack called QHosts, change DNS settings (Confirmed [2]).

### No ATT&CK software objects

The library's ATT&CK data has no software object for Slammer, Blaster, Sobig, Welchia, Mimail, BugBear, Agobot, sdbot, GT-bot, Deloder, Fizzer or Swen, and no group or campaign object for any 2003 worm crew, so any binding for the year's worms is technique-level only (Demonstrated [89][93]).

## Part 4: the compromised project servers

### GNU (March to August)

CA-2003-21 (13 Aug) reported that the system housing the GNU project's primary FTP servers, gnuftp.gnu.org (aliased ftp.gnu.org and alpha.gnu.org), had been root compromised, reportedly in March 2003 (Confirmed [1]). No source distributions were believed modified. The FSF published PGP-signed lists of known-good MD5 hashes, and CERT/CC warned that timestamps and file sizes are not enough to detect modification (Confirmed [1]). A root compromise of a central software archive went unannounced for about five months (Confirmed [1]; Inferred for the span). ATT&CK's later name for the risk is Compromise Software Supply Chain, T1195.002, but no tampering was found, so this study records the risk and does not bind the technique as observed (Inferred).

### Debian (November)

Debian's investigation report of 2 December says that from 17:00 UTC on 19 November an attacker used a sniffed password to log into the project machines klecker and master, then installed rootkits on klecker, master, murphy and gluck, using the Linux kernel do_brk() flaw. The boundary-check fix had been applied upstream in September and October, and Linux 2.4.23, released on 28 November, carried it (Confirmed [38]). Kernel oopses and AIDE alerts led to discovery on 20 November, the project announced the compromise at 10:45 UTC on 21 November, and the package archives were verified as unaltered (Confirmed [38]). The report does not say where the first password was sniffed; it says the attacker reached gluck the next day with a password sniffed on master, and that the SucKIT root-kit includes password sniffing (Confirmed [38]).

### What the two share

Both were root compromises of the servers that distribute free software, Debian verified its archives as unaltered, CERT/CC said no GNU distributions were believed modified, and both told users how to verify (Confirmed [1][38]; the comparison is Inferred). The [npm supply-chain study](/case-studies/NPM_SUPPLY_CHAIN_ATTACKS.md), the [xz Utils backdoor study](/case-studies/XZ_UTILS_BACKDOOR_2024.md), the [Hugging Face supply-chain study](/case-studies/HUGGING_FACE_SUPPLY_CHAIN.md) and [SolarWinds SUNBURST](/case-studies/SOLARWINDS_SUNBURST.md) record what happens when an intruder does change trusted code (Inferred).

## Part 5: the grid and the plant

### Slammer at Davis-Besse

The US-Canada Power System Outage Task Force's final report (April 2004, chapter 9) states that in January 2003 the Slammer worm took down monitoring computers at FirstEnergy's idled Davis-Besse nuclear plant, and relays a NERC report that concluded the infection caused no outages but blocked commands that operated other power utilities (Confirmed [35][36]). The NERC report and the NRC's own Information Notice 2003-14 were not opened.

Kevin Poulsen's account for SecurityFocus, republished by The Register on 20 August 2003, gives the path. Slammer entered through a contractor's network and a T1 link into the plant's business network that bypassed the plant firewall, which did block Slammer's port; it then reached an unpatched Windows server on the plant network. The Safety Parameter Display System crashed at 16:50 and the Plant Process Computer at 17:13; the display system was out for nearly five hours and had an analog backup the worm did not affect. The plant had been offline since February 2002 (Reported [37]). Poulsen's sources were an April 2003 FirstEnergy e-mail to the NRC and a March INPO advisory, neither opened here (Reported [37]).

### The Northeast blackout

The blackout began a few minutes after 16:00 EDT on 14 August and affected an estimated 50 million people and 61,800 MW of load in eight US states and Ontario (Confirmed [36]). Shortly after 14:14 EDT the alarm and logging system in FirstEnergy's control room failed and stayed down until after the blackout; neither the operators nor IT support knew it had failed. FirstEnergy's energy management system was a GE Harris XA21, in service since 1995 and not running the current release, and MISO's state estimator had been ineffective from about 12:15 EDT (Confirmed [36]).

The task force's Security Working Group, whose cyber sub-team was led by CERT/CC and the RCMP, issued interim findings in November 2003 and final findings in April 2004. It found no evidence that malicious actors caused or contributed to the outage, and no evidence that worms then on the Internet, Blaster included, affected the generation or delivery systems of the companies involved; it reviewed a DHS and NCS correlation study of Blaster. It called al-Qaeda claims of responsibility not consistent with its findings, and said a software failure not linked to malicious activity may have contributed significantly (Confirmed [35][36]). It observed weaknesses all the same: unnecessary services left running by default, loose access and perimeter control, poor patch and configuration management, and SCADA links to other systems that introduced vulnerabilities. Recommendations 32 to 34 cover cyber security (Confirmed [36]).

### Policy that followed

HSPD-7 (17 Dec) set national policy for identifying, prioritizing and protecting physical and cyber critical infrastructure. It made DHS the focal point for the security of cyberspace (para 16), designated sector-specific agencies (para 18), required agency protection plans to OMB by July 2004 (para 34) and superseded PDD-63 of 22 May 1998 (para 37) (Confirmed [59]). The [ICS ATT&CK Atlas](/ICS_ATTACK_ATLAS.md), the [ICS attacks and advisories study](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md) and [Stuxnet](/case-studies/STUXNET.md) carry the industrial thread forward (Inferred).

## Part 6: the state record

### Snake begins (development, not operations)

The joint advisory AA23-129A (9 May 2023), from the FBI, NSA, CISA, the Cyber National Mission Force, the UK NCSC and Canadian and other partners, says the FSB began developing Snake as "Uroburos" in late 2003, that initial versions appear to have been completed around early 2004 with operations shortly after, and that the original versions were written entirely in C (Confirmed [76]). It attributes Snake operations to a known unit within FSB Center 16 that also operates the Turla toolset, with daily operations from an FSB facility in Ryazan (Confirmed [76]). ATT&CK's [Uroburos (S0022)](/mitre/software/S0022.md), alias Snake, version 2.1, says it has been upgraded nearly constantly since its initial development in 2003 and is used by Turla (Confirmed [77]). ATT&CK's [Turla (G0010)](/mitre/groups/G0010.md), version 5.1, attributes the group to the FSB and dates its victims since at least 2004 (Confirmed [78]). 2003 is therefore a development date, not an operations date (Inferred). The [Russia study](/case-studies/THREAT_ACTORS_RUSSIA.md) is the home and already records the late-2003 date (Demonstrated [96]).

### Regin and EQUATIONDRUG (vendor reconstructions)

Kaspersky GReAT's Regin report of 24 November 2014 says it is unknown exactly when the first Regin samples were created and that some carry timestamps dating back to 2003 (Confirmed [79]). Kaspersky judges Regin likely nation-state supported, warns that its metadata could be an intentional false flag, names no state and counts 27 victims in 14 countries (Reported [79]). ATT&CK's [Regin (S0019)](/mitre/software/S0019.md), version 1.2, repeats the 2003 timestamps, links no group and lists eleven techniques from the Kaspersky report (Confirmed [80]). Compile timestamps can be altered, so this study treats 2003 as the earliest claimed date, not a proven one (Inferred).

Kaspersky's Equation Group Q&A (version 1.5, February 2015) says EQUATIONDRUG was developed between 2003 and 2013 as an upgrade from EQUATIONLASER, was later replaced by GrayFish, and reached victims after the DOUBLEFANTASY validator (Confirmed [81]). The same Q&A puts EQUATIONLASER at around 2001 to 2003, notes that EQUATIONDRUG used virtual file systems as Regin did, and reads differences in RC5 code as a sign that Equation and Regin are two different entities (Reported [81]). ATT&CK's [Equation (G0020)](/mitre/groups/G0020.md), version 1.2, lists four techniques, among them T1564.005 Hidden File System (an encrypted virtual file system), with no dates and no nation, and neither ATT&CK nor the library has an EquationDrug software object (Confirmed [82]). The [United States actors study](/case-studies/THREAT_ACTORS_UNITED_STATES.md) is the home for both; [other states](/case-studies/THREAT_ACTORS_OTHER_STATES.md) and [the hacker and the state](/case-studies/HACKER_AND_THE_STATE_CASES.md) also mention Regin, and [the NSA and CIA tool leaks](/case-studies/NSA_CIA_TOOL_LEAKS.md) covers Equation (Demonstrated [96]).

### Storm Cloud

Kaspersky and King's College London researchers wrote in 2017 that Storm Cloud is the codename for the evolved toolkit the Moonlight Maze operators used after 1999, and that its story leaked with little fanfare in a 2003 Wall Street Journal article that mentions LOKI2 (Reported [83]). The Journal article was not opened. The [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) is the home for Moonlight Maze.

### Titan Rain

The library has no other study of Titan Rain, and no ATT&CK group, software or campaign object covers it (Demonstrated [96][89]). Everything here is TIME's reporting (Reported). TIME wrote on 29 August 2005 that federal investigators code-named a cyberespionage ring Titan Rain; Sandia analyst Shawn Carpenter first saw it in a September 2003 break-in at Lockheed Martin, followed by a similar attack at Sandia, and traced it to three routers in Guangdong [84]. TIME wrote that documents it obtained show that since 2003 the intruders compromised Redstone Arsenal, NASA and the World Bank and stole Army flight-planning software [85]. TIME reported that the FBI pursued possible Chinese government involvement, but officials said they did not know whether the spying was official, and China's State Council Information Office called the charges groundless [85]. TIME's third page dates Carpenter's first Titan Rain discoveries to March 2004 and says the Army passed his work to the FBI by October 2004 [86]. A separate TIME piece of 25 August 2005 says the group had attacked US government targets since 2003 and that on 1 November 2004 scans from southern China hit unclassified systems at Fort Huachuca, DISA, the Naval Ocean Systems Center and the Army Space and Strategic Defense installation [87]. This study binds no ATT&CK object to Titan Rain and does not treat it as a confirmed state operation (Inferred). The [China study](/case-studies/THREAT_ACTORS_CHINA.md) is the library's home for China-attributed activity.

### The Iraq war

The New York Times reported in August 2009, on unnamed officials, that in 2003 the Pentagon and US intelligence agencies planned a cyberattack to freeze Saddam Hussein's bank accounts before the invasion, and that it was never approved for fear of worldwide financial collateral damage (Reported [88]). The same article says approval was given to cripple Iraq's military and government communications in the war's first hours, including jamming and digital attacks on telephone networks, which temporarily disrupted phone service in neighbouring countries (Reported [88]). No primary government record was opened. The [United States actors study](/case-studies/THREAT_ACTORS_UNITED_STATES.md) is the library's home for US operations.

### The government's own framing

The National Strategy to Secure Cyberspace (February 2003) says that in peacetime America's enemies may spy on government, university research centers and companies, and may map US information systems to prepare for cyber strikes (Confirmed [58]). It is a policy statement, not a record of an operation (Inferred).

### The blackout as a claimed attack

Claims of responsibility for the 14 August blackout came from al-Qaeda; the task force said they were not consistent with its findings (Confirmed [35]).

## Part 7: crime and prosecutions

### Extortion and intrusion from abroad

- **Zezev.** Oleg Zezev, IT chief at Kazkommerts Securities in Almaty, was convicted on 26 February 2003 of hacking Bloomberg L.P. and attempting to extort $200,000 from Michael Bloomberg, and sentenced on 1 July 2003 to 51 months (Confirmed [39]). The [2000 chronicle](/case-studies/CHRONICLE_2000.md) records the August 2000 London arrest.
- **Ivanov.** Alexey Ivanov of Chelyabinsk was sentenced in the District of Connecticut on 25 July 2003 to 48 months for intrusion, card theft, fraud and extortion against dozens of US computers; the judge found an aggregate loss of about $25 million (Confirmed [43]). The [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) is the home.

### Blaster prosecutions (summary)

Part 3 gives the Parson and juvenile cases (Confirmed [44][45][48]).

### Media and reputation

- **Al Jazeera.** In March 2003 John William Racine II sent Network Solutions a forged photo ID and authorization form in the name of Al Jazeera's systems administrator, took over the Aljazeera.net domain account, redirected its web traffic to his own page and intercepted about 300 e-mails. He admitted it to the FBI on 26 March and agreed to plead guilty on 12 June (Confirmed [41]).
- **The New York Times.** SDNY charged Adrian Lamo on 9 September 2003 by a two-count complaint over the 26 February 2002 intrusion into the New York Times network, and he surrendered in Sacramento that day (Confirmed [46]). The [Mitnick intrusions study](/case-studies/MITNICK_INTRUSIONS.md) is the home; the [2002 chronicle](/case-studies/CHRONICLE_2002.md) dates the intrusion itself.
- **Spoofed spam.** Allan Eric Carlson was indicted on 25 September 2003 (unsealed with his arrest on 7 October) for hacking computers to send spam with the spoofed addresses of Philadelphia Inquirer and Daily News reporters and the Phillies, flooding those accounts with bounced mail (Confirmed [47]).
- **Publicity by intrusion.** Brett Edward O'Keefe, president of the San Diego firm Forensic Tec Solutions, was indicted (announced 29 September) for a conspiracy to access NASA, Army, Navy, DOE and NIH computers and take files to the media to publicize his company (Confirmed [49]).

### Insiders and those with access

- **NASA Glenn.** On 13 February 2003 an information was filed against Dino Amato, a contractor at NASA Glenn Research Center, for repeatedly mailing a "ZIP-42" archive to NASA's mail server from 5 to 14 November 2001, slowing or stopping mail processing, with about $12,000 in losses (Confirmed [40]).
- **Acxiom.** Daniel Baas, a systems administrator at a Cincinnati firm that did business with Acxiom, was charged in August and pleaded guilty on 18 December 2003 to exceeding authorized access. He downloaded an encrypted password file, cracked about 300 passwords including a "master key", and downloaded other customers' files containing personal information. The cost to Acxiom was more than $5.8 million, and the data was not used for criminal or commercial purposes (Confirmed [55]).
- **Los Angeles County.** Under Operation Cyber Sweep, Walter Wiggs, a technician laid off by the company that built the hotline's voice-response software, agreed in a plea agreement filed on 19 November to taking down the Los Angeles County Child Protection Hotline from 1 to 4 July 2003 by deleting configuration files (Confirmed [52]).

### Kiosks and stores

- **Kinko's.** Juju Jiang pleaded guilty in SDNY on 10 July 2003 (release dated 11 July). From 14 February 2001 to 20 December 2002 he installed keylogging software on Kinko's terminals in Manhattan to collect customers' usernames and passwords, then used them to access bank accounts and open online accounts (Confirmed [42]). The [2002 chronicle](/case-studies/CHRONICLE_2002.md) records his December 2002 arrest.
- **Lowe's.** Brian Salcedo, Adam Botbyl and Paul Timmins were indicted in the Western District of North Carolina on 19 November 2003 on 16 counts (release dated 9 December). From October to 9 November they compromised the wireless network of a Lowe's store in Southfield, Michigan, reached Lowe's central system in North Wilkesboro and other stores, and installed a program designed to capture customers' card data (Confirmed [50]). Salcedo was sentenced on 15 December 2004 to 108 months; the release calls Mitnick's 68 months the longest previous federal hacking sentence (Confirmed [51]). The [e-commerce threats study](/case-studies/ECOMMERCE_THREATS.md) carries the payment-card thread forward (Inferred).

### Organized cybercrime and the big sweeps (summary)

- **Operation Firewall.** The Secret Service says Operation Firewall began in July 2003 as an access-device fraud investigation that identified Shadowcrew, Carderplanet and Darkprofits; arrests were announced in October 2004 (Confirmed [57]).
- **Weaknees and Cyberslam.** In October 2003 commissioned DDoS attacks halted the Los Angeles retailer Weaknees for nearly two weeks with more than $200,000 in losses, and Rapid Satellite was also attacked; the case, Operation Cyberslam, is described in a 2008 indictment release that names Agobot (Confirmed [56]).
- **Operation Cyber Sweep.** The Attorney General announced it on 20 November 2003. It began on 1 October and produced more than 125 arrests or convictions, more than 70 indictments and more than 90 warrants, with more than 125,000 victims and losses above $100 million, coordinated by 34 US Attorneys' offices with the FBI, the Postal Inspection Service, the FTC, the Secret Service and ICE (Confirmed [53]).

[Four Books on Cybercrime](/case-studies/CYBERCRIME_FOUR_BOOKS.md) is the home for Operation Firewall, Agobot and Weaknees, and Cyberslam (Demonstrated [98]).

## Part 8: law, policy and standards

### United States

- **The National Strategy to Secure Cyberspace (February).** It sets out a DHS-coordinated National Cyberspace Security Response System, encourages ISACs, and says good security includes regular patching and virus updates (Confirmed [58]). The [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) is the home.
- **California SB 1386 (1 July).** Chapter 915, Statutes of 2002, approved on 25 September 2002, became operative on 1 July 2003 and made notice of a breach of unencrypted personal information a legal duty (Confirmed [62]). The dot-com era study is the home.
- **FACTA (4 December).** The Fair and Accurate Credit Transactions Act of 2003 (Pub. L. 108-159, H.R. 2622) covers fraud and active-duty alerts (s.112), truncation of card numbers on electronically printed receipts to no more than the last 5 digits with no expiration date (s.113), a summary of rights for identity-theft victims (s.151), free annual consumer reports (s.211) and a rule on disposing of consumer report records (s.216) (Confirmed [61]).
- **CAN-SPAM (16 December).** Pub. L. 108-187 (S. 877), effective 1 January 2004 except section 9 (Confirmed [60]). DOJ and Commerce issued a joint statement on spam legislation on 21 November (Confirmed [54]). The dot-com era study is the home.
- **HSPD-7 (17 December).** Part 5.

### International

- **Council of Europe ETS 189 (28 January).** The Additional Protocol to the Convention on Cybercrime, concerning acts of a racist and xenophobic nature committed through computer systems, was done at Strasbourg; its entry-into-force date was not checked (Confirmed [64]).
- **UK PECR (11 December).** The Privacy and Electronic Communications (EC Directive) Regulations 2003, SI 2003/2426, made and laid on 18 September and in force on 11 December, implement Directive 2002/58/EC (Confirmed [63]).
- **WSIS (12 December).** Section B5 of the Geneva Declaration of Principles (paras 35 to 37) calls for a global culture of cyber-security with all stakeholders and for preventing the use of ICTs for criminal and terrorist purposes (Confirmed [66]).
- **UN A/RES/58/199 (23 December).** Adopted at the General Assembly's 78th plenary meeting, it recalls resolution 57/239 of 20 December 2002, and its annex lists elements for protecting critical information infrastructure, starting with emergency warning networks for cyber vulnerabilities, threats and incidents (Confirmed [65]).

### Standards

- **RFC 3546 (June).** TLS Extensions, Standards Track, updates RFC 2246 and defines the server_name extension, Server Name Indication (Confirmed [72]).
- **NIST SP 800-42 (October).** Guideline on Network Security Testing; withdrawn on 30 September 2008 and superseded by SP 800-115 (Confirmed [67]).
- **NIST SP 800-50 (October).** Building an IT Security Awareness and Training Program; withdrawn on 12 September 2024 and superseded by Revision 1 (Confirmed [68]).
- **Just after the year.** SP 800-61, the Computer Security Incident Handling Guide, followed in January 2004, superseding SP 800-3 of 1991; FIPS 199 in February 2004; and the original SP 800-53 only in February 2005, so no SP 800-53 control catalog existed in 2003 (Confirmed [69][70][71]).

### Industry

Windows Server 2003's support lifecycle started on 28 May 2003 (Itanium editions 19 June) and its extended support ended on 14 July 2015 (Confirmed [17]). Microsoft's move to monthly releases and its reward program are in Parts 2 and 3.

## Part 9: the defender view

**The race was fix to worm, and defenders lost it twice.** MS02-039 preceded Slammer by six months and MS03-026 preceded Blaster by 26 days (Confirmed [5][8][1]; Inferred for the intervals). The [Log4Shell study](/case-studies/LOG4SHELL.md) shows the other case, exploitation before the fix, and the [zero-day market study](/case-studies/ZERO_DAY_MARKET_EVENTS.md) follows that market (Inferred).

**Border filtering limited spread; it did not prevent infection.** CERT said so for UDP 1434, and VU#568148 said perimeter blocks leave inside attackers free to exploit the RPC flaw (Confirmed [1][4]). VU#484891's workaround was still to block 1434/udp at the border (Confirmed [3]).

**The host firewall entered the playbook.** MS03-026 and CA-2003-20 named Internet Connection Firewall, which blocks inbound RPC by default on XP and Server 2003, as the step before patching, and CERT advised disconnecting infected hosts to clean them first (Confirmed [8][1]).

**Signatures could not keep up.** CERT said worms now spread in minutes and that Sobig.E beat signatures current for earlier variants; Fizzer, by F-Secure's account, killed anti-virus tasks (Confirmed [2]; Reported [32]).

**Defaults and passwords again.** CA-2003-08 needed only null or weak Administrator passwords on SMB shares (Confirmed [1]). The Acxiom case turned a cracked password file into about 300 passwords and a "master key" (Confirmed [55]).

**Integrity checking found one quiet intrusion and vouched for both archives.** The FSF answered the GNU compromise with signed hash lists, and Debian found its intruder through AIDE and kernel crashes (Confirmed [1][38]).

**Security software is software.** Snort and OpenSSL both shipped remotely exploitable flaws in 2003 (Confirmed [1]).

**Paths around the firewall matter as much as the firewall.** In Poulsen's account the Davis-Besse firewall blocked Slammer's port and the worm came in through a contractor link (Reported [37]). The task force named poor patch management, loose perimeter control and SCADA links among the weaknesses it observed (Confirmed [36]).

**Patching got a calendar.** Microsoft's monthly cycle, announced on 9 October and begun on 15 October, gave defenders a predictable release day (Confirmed [14][10]; the effect is Inferred).

## Part 10: MITRE mappings

No 2003 record carries an ATT&CK, CWE, CAPEC or CVSS id from the time (Confirmed [73][74][75]; Inferred for ATT&CK). Every Enterprise and ICS binding below is this study's later mapping (Inferred). The exceptions are the objects ATT&CK itself dates to 2003: Uroburos (S0022) and Regin (S0019) (Confirmed [77][80]). Every id was checked against the library's data files and the generated pages under `mitre/` (Demonstrated [89][90][91][92][93][94][95]). Names and tactics are those of ATT&CK v20.0 as the library carries them.

The Basis column says how strong each tie is, as in the [2016 chronicle](/case-studies/CHRONICLE_2016.md). **Listed** means ATT&CK itself lists the id for the event or object. **Described** means a primary source describes the behavior and this study assigns the id. **Reported** means only a secondary source supports the behavior. **Inferred** means no source describes the behavior in enough detail and the mapping rests on the study's reading.

### ATT&CK Enterprise techniques

| Id | Name (ATT&CK v20.0) | Tactic(s) | Basis | Dated event or report | Sources |
|---|---|---|---|---|---|
| [`T1190`](/mitre/techniques/T1190.md) | Exploit Public-Facing Application | initial-access | Described | Slammer on the SQL Server Resolution Service (CA-2003-04, 25 Jan); the IIS 5.0 WebDAV ntdll.dll overflow, actively exploited (CA-2003-09, 17 Mar) | [1][7] |
| [`T1210`](/mitre/techniques/T1210.md) | Exploitation of Remote Services | lateral-movement | Described | Slammer host to host (25 Jan); public DCOM RPC exploits (CA-2003-19, 31 Jul); Blaster (CA-2003-20, 11 Aug); Welchia through the same flaw (18 Aug) | [1][21][33] |
| [`T1046`](/mitre/techniques/T1046.md) | Network Service Discovery | discovery | Described | CA-2003-08 tools scan TCP 445 within the same /16 (11 Mar); scanning for TCP 135 (CA-2003-19, 31 Jul); Blaster scans for more hosts (11 Aug) | [1] |
| [`T1078.001`](/mitre/techniques/T1078-001.md) | Default Accounts | stealth, persistence, privilege-escalation, initial-access | Described | Null or weak Administrator passwords on SMB shares (CA-2003-08, 11 Mar) | [1] |
| [`T1110.001`](/mitre/techniques/T1110-001.md) | Password Guessing | credential-access | Inferred | The same compromises; the advisory says weak passwords, not how they were found | [1] |
| [`T1021.002`](/mitre/techniques/T1021-002.md) | SMB/Windows Admin Shares | lateral-movement | Described | CA-2003-08 compromises over SMB shares on 445/tcp (11 Mar) | [1] |
| [`T1071`](/mitre/techniques/T1071.md) | Application Layer Protocol | command-and-control | Described | CA-2003-08 tools connect to IRC for commands (11 Mar) | [1] |
| [`T1584.005`](/mitre/techniques/T1584-005.md) | Botnet | resource-development | Described | Denial-of-service tools installed on hosts commanded over IRC (CA-2003-08); the commissioned DDoS on Weaknees (Oct), in a case the 2008 release ties to Agobot | [1][56] |
| [`T1498`](/mitre/techniques/T1498.md) | Network Denial of Service | impact | Described | Commissioned DDoS on Weaknees and Rapid Satellite (Oct); the RPCSDBOT variant's DDoS on Microsoft (arrest 26 Sep). Slammer's network degradation was a side effect of scanning, not a payload (25 Jan) | [56][48][1] |
| [`T1498.001`](/mitre/techniques/T1498-001.md) | Direct Network Flood | impact | Described | Blaster's TCP SYN flood against windowsupdate.com, confirmed in CERT's lab (11 Aug) | [1] |
| [`T1499.001`](/mitre/techniques/T1499-001.md) | OS Exhaustion Flood | impact | Inferred | The same SYN flood read as a connection-table exhaustion attack, as the home study maps it | [1][97] |
| [`T1105`](/mitre/techniques/T1105.md) | Ingress Tool Transfer | command-and-control | Described | Blaster retrieves its executable from the compromising host (11 Aug); Sobig.F's scheduled contact to fetch further code (22 Aug, as CERT believed) | [1][2] |
| [`T1547.001`](/mitre/techniques/T1547-001.md) | Registry Run Keys / Startup Folder | persistence, privilege-escalation | Described | Blaster's Run value (11 Aug); Sobig.F's Run key (22 Aug) | [1][2] |
| [`T1059.003`](/mitre/techniques/T1059-003.md) | Windows Command Shell | execution | Described | Public RPC exploits create a privileged back-door command shell (CA-2003-19, 31 Jul) | [1] |
| [`T1571`](/mitre/techniques/T1571.md) | Non-Standard Port | command-and-control | Inferred | Some of those shells listen on TCP 4444 (CA-2003-19); a listening port, so a weak fit | [1] |
| [`T1566.001`](/mitre/techniques/T1566-001.md) | Spearphishing Attachment | initial-access | Inferred | Mass-mailed, not targeted, so the closest fit only: Mimail's zipped MHTML (1 Aug), Sobig.F's .pif attachments (22 Aug) | [2] |
| [`T1204.002`](/mitre/techniques/T1204-002.md) | Malicious File | execution | Described | Mimail as a fake administrator account-expiry notice (IN-2003-02); Sobig.F's attachments (IN-2003-03) | [2] |
| [`T1203`](/mitre/techniques/T1203.md) | Exploitation for Client Execution | execution | Described | IE VU#865940 exploited to install tools (IN-2003-04, 1 Oct); Mimail installs when viewed on a vulnerable system (2 Aug) | [2] |
| [`T1685`](/mitre/techniques/T1685.md) | Disable or Modify Tools | defense-impairment | Reported | Fizzer kills anti-virus tasks (8 May). T1562.001 is revoked and superseded by T1685 in the library's data | [32][92] |
| [`T1684.002`](/mitre/techniques/T1684-002.md) | Email Spoofing | stealth | Described | Sobig.B and Sobig.C spoof Microsoft addresses; Carlson's spam with reporters' spoofed addresses (indicted 25 Sep). T1672 is revoked and superseded by T1684.002 | [15][47][92] |
| [`T1584.001`](/mitre/techniques/T1584-001.md) | Domains | resource-development | Described | Racine takes over the Aljazeera.net domain account at Network Solutions (Mar) | [41] |
| [`T1684.001`](/mitre/techniques/T1684-001.md) | Impersonation | stealth | Described | Racine's forged photo ID and authorization form in the name of Al Jazeera's systems administrator (Mar). T1656 is revoked and superseded by T1684.001 | [41][92] |
| [`T1114`](/mitre/techniques/T1114.md) | Email Collection | collection | Described | Racine intercepts about 300 e-mails (Mar) | [41] |
| [`T1499`](/mitre/techniques/T1499.md) | Endpoint Denial of Service | impact | Described | Amato's repeated "ZIP-42" archives slow or stop NASA's mail server (Nov 2001; charged 13 Feb 2003) | [40] |
| [`T1078`](/mitre/techniques/T1078.md) | Valid Accounts | stealth, persistence, privilege-escalation, initial-access | Described | Debian intruder logs in with a sniffed password (19 Nov); Baas uses cracked passwords and a "master key" (plea 18 Dec); Jiang uses captured credentials (plea 10 Jul) | [38][55][42] |
| [`T1068`](/mitre/techniques/T1068.md) | Exploitation for Privilege Escalation | privilege-escalation | Described | The do_brk() kernel flaw on Debian machines (19 Nov) | [38] |
| [`T1014`](/mitre/techniques/T1014.md) | Rootkit | stealth | Described | Rootkits on klecker, master, murphy and gluck (19 Nov) | [38] |
| [`T1110.002`](/mitre/techniques/T1110-002.md) | Password Cracking | credential-access | Described | Baas cracks an encrypted password file for about 300 passwords (charged Aug; plea 18 Dec) | [55] |
| [`T1213`](/mitre/techniques/T1213.md) | Data from Information Repositories | collection | Inferred | Baas downloads other customers' files from Acxiom's systems | [55] |
| [`T1056.001`](/mitre/techniques/T1056-001.md) | Keylogging | collection, credential-access | Described | Jiang's keylogging software on Kinko's terminals (Feb 2001 to Dec 2002; plea 10 Jul) | [42] |
| [`T1669`](/mitre/techniques/T1669.md) | Wi-Fi Networks | initial-access | Described | The Lowe's store wireless network in Southfield (Oct to 9 Nov) | [50] |
| [`T1056`](/mitre/techniques/T1056.md) | Input Capture | collection, credential-access | Inferred | A program installed to capture Lowe's customers' card data; the release does not say how it captured them | [50] |
| [`T1485`](/mitre/techniques/T1485.md) | Data Destruction | impact | Described | Wiggs deletes configuration files and takes down a county child-protection hotline (1 to 4 Jul; plea agreement filed 19 Nov) | [52] |
| [`T1199`](/mitre/techniques/T1199.md) | Trusted Relationship | initial-access | Reported | Slammer enters Davis-Besse through a contractor's network and T1 link (Jan) | [37] |
| [`T1657`](/mitre/techniques/T1657.md) | Financial Theft | impact | Described | Zezev's attempted $200,000 extortion (convicted 26 Feb; the intrusion predates 2003); Ivanov's extortion (sentenced 25 Jul) | [39][43] |

Left out on purpose: [T1195.002](/mitre/techniques/T1195-002.md) Compromise Software Supply Chain for the GNU FTP server, because no distribution was found modified; it is a risk, not an observed technique, and is not in the layer (Confirmed [1]; Inferred). [T1040](/mitre/techniques/T1040.md) Network Sniffing for Debian, because the report does not say how the first password was captured, and the later capture was by the rootkit on the host, not on the network (Confirmed [38]; Inferred). Fizzer's self-updating, which rests on a Reported source and adds nothing to T1105 (Reported [32]). The QHosts DNS-settings change, premium-rate dialing and registry reading in IN-2003-04, which the incident note describes in a sentence each (Confirmed [2]; Inferred). O'Keefe's alleged access, which the release does not describe technically (Confirmed [49]). The state platforms' techniques, which go in their own table below.

### Techniques ATT&CK lists for objects it dates to 2003

ATT&CK lists these techniques for Regin (S0019), whose timestamps it dates back to 2003, and for Equation (G0020), whose EQUATIONDRUG platform Kaspersky dates from 2003 (Confirmed [80][82]); the library's data records the same counts, 11 techniques for S0019 and 4 for G0020 (Demonstrated [89]). ATT&CK draws them from Kaspersky's 2014 and 2015 analyses of later platforms, not from a dated 2003 event, so they are not in this study's Navigator layer (Confirmed [80][82]; Inferred). S0019 lists eleven techniques; the six below are those this study read on its page.

| Id | Name (ATT&CK v20.0) | Tactic(s) | Object | Basis | Sources |
|---|---|---|---|---|---|
| [`T1564.005`](/mitre/techniques/T1564-005.md) | Hidden File System | stealth | S0019 Regin; G0020 Equation (EQUATIONDRUG's virtual file systems, Inferred) | Listed (object) | [80][82][81] |
| [`T1564.004`](/mitre/techniques/T1564-004.md) | NTFS File Attributes | stealth | S0019 Regin | Listed (object) | [80] |
| [`T1095`](/mitre/techniques/T1095.md) | Non-Application Layer Protocol | command-and-control | S0019 Regin | Listed (object) | [80] |
| [`T1021.002`](/mitre/techniques/T1021-002.md) | SMB/Windows Admin Shares | lateral-movement | S0019 Regin | Listed (object) | [80] |
| [`T1090.002`](/mitre/techniques/T1090-002.md) | External Proxy | command-and-control | S0019 Regin | Listed (object) | [80] |
| [`T1056.001`](/mitre/techniques/T1056-001.md) | Keylogging | collection, credential-access | S0019 Regin | Listed (object) | [80] |
| [`T1120`](/mitre/techniques/T1120.md) | Peripheral Device Discovery | discovery | G0020 Equation | Listed (group) | [82] |
| [`T1480.001`](/mitre/techniques/T1480-001.md) | Environmental Keying | stealth | G0020 Equation | Listed (group) | [82] |
| [`T1542.002`](/mitre/techniques/T1542-002.md) | Component Firmware | stealth, persistence | G0020 Equation | Listed (group) | [82] |

Uroburos (S0022) carries many techniques on its ATT&CK page, drawn from the 2023 advisory and earlier reporting on later versions; none is presented here as observed in 2003 (Confirmed [77]; Inferred).

### ATT&CK for ICS techniques

The Davis-Besse event touches an industrial site, so it gets its own table (Inferred). Both ids and names are in the library's ICS data; the library has no generated ICS technique pages, so the ids link to ATT&CK (Demonstrated [91]).

| Id | Name | Tactic(s) | Basis | Dated event or report | Sources |
|---|---|---|---|---|---|
| [`T0866`](https://attack.mitre.org/techniques/T0866/) | Exploitation of Remote Services | initial-access, lateral-movement | Reported | Slammer reaches an unpatched Windows server on the plant network (Jan) | [37][91] |
| [`T0829`](https://attack.mitre.org/techniques/T0829/) | Loss of View | impact | Described | Monitoring computers taken down (task force); the Safety Parameter Display System out for nearly five hours (Poulsen) | [35][37][91] |

Left out: T0815 Denial of View, which ATT&CK defines as a temporary failure that recovers once the interference ceases; a display system that crashed and stayed down for nearly five hours fits T0829's sustained loss needing a restart (Inferred; Reported [37]). T0826 Loss of Availability, since the plant had been offline since February 2002 by Poulsen's account and no production was lost (Reported [37]; Inferred). T0813 Denial of Control for the commands NERC said were blocked at other utilities, because the task force's one-sentence summary is too thin to bind (Confirmed [35]; Inferred). No ATT&CK for ICS object covers the event (Demonstrated [91]).

### ATT&CK groups, software and campaigns

| Object | Id | Binding | Sources |
|---|---|---|---|
| Uroburos (Snake) | [S0022](/mitre/software/S0022.md) | Bound for its development: ATT&CK says initial development in 2003; AA23-129A says late 2003, with initial versions around early 2004 | [77][76] |
| Turla | [G0010](/mitre/groups/G0010.md) | Bound with a caveat: the group that uses Uroburos; ATT&CK dates its victims since at least 2004, so 2003 is not an operations date | [78][76] |
| Regin | [S0019](/mitre/software/S0019.md) | Bound with a caveat: ATT&CK and Kaspersky say some timestamps date back to 2003; no group or nation is linked | [80][79] |
| Equation | [G0020](/mitre/groups/G0020.md) | Bound with a caveat: Kaspersky dates EQUATIONDRUG from 2003; ATT&CK carries no dates, nation or EquationDrug software object | [82][81] |

No campaign object is bound. No ATT&CK object covers Titan Rain, the Iraq war operations or any 2003 worm (Confirmed [89]; Demonstrated [93]).

### CWE and CAPEC

NVD's CWE ids for the year's CVEs can only have been assigned after the CWE List's first release in 2006 (Confirmed [73]; Inferred for the assignment dates). Rows marked NVD carry the CWE NVD lists; the others are this study's classes (Inferred). Names are those in the library's CWE and CAPEC data, and every CAPEC listed has a page under `/mitre/capec/` (Demonstrated [95][93]). Where the library's technique data lists a CAPEC entry on a technique, the row says so (Demonstrated [90]).

| CWE | Weakness (library name) | Basis | 2003 record | CAPEC |
|---|---|---|---|---|
| CWE-119 | Improper Restriction of Operations within the Bounds of a Memory Buffer | NVD | SQL Server Resolution Service (CVE-2002-0649), used by Slammer | [CAPEC-100](/mitre/capec/CAPEC-100.md) Overflow Buffers |
| CWE-415 | Double Free | NVD | OpenSSL ASN.1 (CVE-2003-0545, CA-2003-26) | None assigned |
| NVD-CWE-Other | (as NVD lists it) | NVD | DCOM RPC (CVE-2003-0352), WebDAV and ntdll.dll (CVE-2003-0109), Snort stream4 (CVE-2003-0209), Sendmail prescan (CVE-2003-0161), Workstation Service (CVE-2003-0812), RPCSS (CVE-2003-0528) | [CAPEC-100](/mitre/capec/CAPEC-100.md), this study's pairing for advisories that describe buffer overflows |
| CWE-1393 and CWE-521 | Use of Default Password; Weak Password Requirements | Study's class | Null or weak Administrator passwords (CA-2003-08, 11 Mar) | [CAPEC-70](/mitre/capec/CAPEC-70.md) Try Common or Default Usernames and Passwords (the library lists it on T1078.001); [CAPEC-49](/mitre/capec/CAPEC-49.md) Password Brute Forcing (on T1110.001); [CAPEC-561](/mitre/capec/CAPEC-561.md) Windows Admin Shares with Stolen Credentials (on T1021.002) |
| CWE-494 | Download of Code Without Integrity Check | Study's class (risk only) | The GNU FTP compromise and CERT's advice to verify signed hashes (CA-2003-21) | [CAPEC-186](/mitre/capec/CAPEC-186.md) Malicious Software Update (the library lists it on T1195.002), risk only |
| none bound | (scanning) | Study's pairing | Scans of TCP 445 and 135 | [CAPEC-300](/mitre/capec/CAPEC-300.md) Port Scanning (the library lists it on T1046) |
| none bound | (persistence) | Study's pairing | Blaster and Sobig.F Run keys | [CAPEC-270](/mitre/capec/CAPEC-270.md) Modification of Registry Run Keys (the library lists it on T1547.001) |
| none bound | (flooding) | Study's pairing | Blaster's SYN flood; the Weaknees attacks | [CAPEC-125](/mitre/capec/CAPEC-125.md) Flooding; [CAPEC-482](/mitre/capec/CAPEC-482.md) TCP Flood (the library lists both on T1498.001) |
| none bound | (credential capture) | Study's pairing | Jiang's keylogger | [CAPEC-568](/mitre/capec/CAPEC-568.md) Capture Credentials via Keylogger (the library lists it on T1056.001) |

The library lists CAPEC-55 Rainbow Table Password Cracking on T1110.002, but the Baas release does not say how the file was cracked, so it is left out (Demonstrated [90]; Confirmed [55]). CAPEC-163 Spear Phishing, listed on T1566.001, is left out because the year's mailers were not targeted (Inferred).

### D3FEND countermeasures

The technique-to-countermeasure links come from the library's D3FEND data unless the row says the pairing is this study's; pairing them with the 2003 advice is this study's reading (Demonstrated [94]; Inferred). Every page exists under `/mitre/d3fend/` (Demonstrated [93]).

| Technique from the record | D3FEND countermeasures | 2003 analogue |
|---|---|---|
| T1190, T1210, T1105 | [Network Traffic Filtering](/mitre/d3fend/network-traffic-filtering.md) (D3-NTF), [Network Traffic Signature Analysis](/mitre/d3fend/network-traffic-signature-analysis.md) (D3-NTSA) | Block 1434/udp at the border (VU#484891); the MS03-026 port blocks; Slammer identifiable by its 376-byte UDP packets [3][8][1] |
| T1190 | [Inbound Traffic Filtering](/mitre/d3fend/inbound-traffic-filtering.md) (D3-ITF) | CA-2003-04's ingress filtering, which limits spread but does not prevent infection [1] |
| T1105, T1571 | [Outbound Traffic Filtering](/mitre/d3fend/outbound-traffic-filtering.md) (D3-OTF) | CA-2003-04's egress filtering; Sobig.F's scheduled contact over UDP 8998 (this study's pairing for Sobig.F) [1][2] |
| T1210 | [Connection Attempt Analysis](/mitre/d3fend/connection-attempt-analysis.md) (D3-CAA) | Scanning on TCP 135 and 445 [1] |
| T1210 (this study's pairing) | [RPC Traffic Analysis](/mitre/d3fend/rpc-traffic-analysis.md) (D3-RTA) | DCOM RPC exploitation; the library's data links this page only to T1558.003 Kerberoasting, not to T1210 [1][94] |
| T1547.001 | [File Integrity Monitoring](/mitre/d3fend/file-integrity-monitoring.md) (D3-FIM); [Registry Key Deletion](/mitre/d3fend/registry-key-deletion.md) (D3-RKD, this study's pairing; the library's data does not link it to T1547.001) | CA-2003-20's recovery removes the Run value [1] |
| T1014 | [File Integrity Monitoring](/mitre/d3fend/file-integrity-monitoring.md) (D3-FIM) | AIDE helped Debian find its rootkits [38] |
| T1078.001, T1110.001, T1110.002 | [Change Default Password](/mitre/d3fend/change-default-password.md) (D3-CDP), [Strong Password Policy](/mitre/d3fend/strong-password-policy.md) (D3-SPP), [Credential Revocation](/mitre/d3fend/credential-revocation.md) (D3-CR) | CA-2003-08's null and weak passwords; Acxiom's cracked password file and "master key" [1][55] |
| T1195.002 (risk) | [Software Update](/mitre/d3fend/software-update.md) (D3-SU), [Software Inventory](/mitre/d3fend/software-inventory.md) (D3-SWI); [Message Authentication](/mitre/d3fend/message-authentication.md) (D3-MAN, this study's pairing) | The FSF's PGP-signed MD5 lists after CA-2003-21 [1] |
| T1190, T1210 (this study's pairing) | [Software Update](/mitre/d3fend/software-update.md) (D3-SU), [System Vulnerability Assessment](/mitre/d3fend/system-vulnerability-assessment.md) (D3-SYSVA) | MS02-039 and MS03-026; Microsoft's scanning tool for the RPC flaws (KB 827363) [5][8] |
| T1190, T1203, T1210, T1068 | [Stack Frame Canary Validation](/mitre/d3fend/stack-frame-canary-validation.md) (D3-SFCV), [Segment Address Offset Randomization](/mitre/d3fend/segment-address-offset-randomization.md) (D3-SAOR), [Process Segment Execution Prevention](/mitre/d3fend/process-segment-execution-prevention.md) (D3-PSEP) | Later memory protections against the year's stack overflows; none was 2003 advice (Inferred) [1] |
| T1566.001, T1204.002 | [Email Filtering](/mitre/d3fend/email-filtering.md) (D3-EF), [File Analysis](/mitre/d3fend/file-analysis.md) (D3-FA), [Executable Allowlisting](/mitre/d3fend/executable-allowlisting.md) (D3-EAL) | Mimail, Sobig.F and the other mass mailers [2] |
| T0866 (ICS) | [Network Traffic Filtering](/mitre/d3fend/network-traffic-filtering.md) (D3-NTF); [Software Update](/mitre/d3fend/software-update.md) (D3-SU, this study's pairing) | The contractor link around the Davis-Besse firewall; the unpatched plant server [37] |

Techniques not named in this table are left without a D3FEND pairing here; none is invented (Inferred). ATT&CK mitigation pages exist for [M1051 Update Software](/mitre/mitigations/M1051.md), [M1037 Filter Network Traffic](/mitre/mitigations/M1037.md), [M1042 Disable or Remove Feature or Program](/mitre/mitigations/M1042.md) (disabling DCOM, as MS03-026 advised) and [M1027 Password Policies](/mitre/mitigations/M1027.md) (Demonstrated [93]).

### Navigator layers

The study's Enterprise techniques are saved as one ATT&CK Navigator layer pinned to ATT&CK v20, [navigator/library-layers/chronicle-2003.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/chronicle-2003.json), in the format of the existing chronicle layers (domain enterprise-attack, navigator 4.9, layer 4.5, described as a curated case-study layer and not an official MITRE mapping) (Demonstrated [99]). It lists the 35 techniques in the Enterprise table under each tactic they carry in v20.0 and is listed on [the Navigator layers page](/navigator/index.md). The Regin and Equation techniques are not in it. Curated layers in that folder must be `enterprise-attack`, so the two Davis-Besse techniques go in a separate ATT&CK for ICS layer, [navigator/case-studies/chronicle-2003-ics.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/case-studies/chronicle-2003-ics.json), domain `ics-attack`. Scores show the basis, not severity, in the house scale set by the 2016 chronicle: 100 where the source or ATT&CK prints the id, 70 where a primary source describes the behavior and this study assigns the id, 50 where only a Reported source supports it, and 40 for an Inferred mapping (Demonstrated [99]). No 2003 source prints an ATT&CK id, so the rows score 70, 50 or 40 (Inferred). Each entry's comment names the source numbers in the Sources table below.

## Cross-cutting themes

**The patch-to-worm gap became the measure of a defense program.** Six months for Slammer, 26 days for Blaster, and the monthly release cycle that followed (Confirmed [5][8][1][14][10]; Inferred for the intervals and the link). The [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) traces the same gap back through Code Red and Nimda (Inferred).

**Speed beat signatures.** CERT's own words were that propagation fell to minutes and that a new Sobig variant beat current signatures (Confirmed [2]). Filtering and host firewalls, not signatures, were the year's fast controls (Inferred).

**Software distribution became a target.** GNU's and Debian's archives were reached at root level within one year; Debian verified its packages intact, no GNU distribution was believed modified, and both relied on integrity checks (Confirmed [1][38]). The [xz Utils](/case-studies/XZ_UTILS_BACKDOOR_2024.md), [npm](/case-studies/NPM_SUPPLY_CHAIN_ATTACKS.md), [Hugging Face](/case-studies/HUGGING_FACE_SUPPLY_CHAIN.md) and [SolarWinds](/case-studies/SOLARWINDS_SUNBURST.md) studies show what happens when trusted code is changed (Inferred).

**Industrial networks met office malware.** A worm built for SQL Server reached a nuclear plant's display system through a contractor link (Confirmed [35]; Reported [37]). The task force's weaknesses list and HSPD-7 put cyber security into critical-infrastructure policy (Confirmed [36][59]). [Stuxnet](/case-studies/STUXNET.md) and the [ICS attacks and advisories study](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md) carry the thread forward (Inferred).

**Law moved from penalties to duties.** SB 1386 made breach notice a duty, FACTA added receipt truncation and identity-theft rights, and CAN-SPAM set rules for commercial mail (Confirmed [62][61][60]). The [Change Healthcare](/case-studies/CHANGE_HEALTHCARE_2024.md) and [e-commerce threats](/case-studies/ECOMMERCE_THREATS.md) studies show how those duties shape the public record now (Inferred).

**State activity was invisible at the time.** Snake's 2003 start came out in 2023, Regin's and EQUATIONDRUG's in 2014 and 2015, and Titan Rain's in 2005, in TIME's reporting on documents, a named analyst and unnamed officials (Confirmed [76][79][81]; Reported [84][85]). The [APT41 study](/case-studies/APT41_PUBLIC_RECORD.md) shows how much more evidence a confident attribution now carries (Inferred).

### What is overstated and what is understated

This section is the study's reading of the record (Inferred).

- **Overstated: 2003 as only a worm year.** Named mass worms and vendor bulletins are the easiest events to date and measure, and CVE records name the worms, so they dominate the record [1][21].
- **Overstated: Slammer's real-world impacts.** The canceled flights, election interference and ATM failures are relayed in the CAIDA paper, not measured [30].
- **Overstated: the blackout as a cyberattack.** The task force found no evidence of malicious cause or worm effect, and called al-Qaeda's claims inconsistent with its findings; it said a non-malicious software failure may have contributed significantly [35][36].
- **Overstated: Davis-Besse as a safety event.** The plant had been offline since February 2002 and the display system had an analog backup, by Poulsen's account; the task force relays that the infection caused no outages [37][35].
- **Overstated: the Blaster arrests as closing the case.** The arrests were for the B and RPCSDBOT variants; Microsoft said in November that the original author was still at large [44][48][15].
- **Overstated: Titan Rain as a confirmed Chinese government operation.** Officials TIME quoted said they did not know whether the spying was official, and China called the charges groundless [85].
- **Overstated: Regin or Equation in 2003 as a named agency's work.** No Kaspersky or ATT&CK record cited here names a state, Kaspersky flags Regin's metadata as a possible false flag, and it reads Equation and Regin as different entities [79][81][82].
- **Overstated: Turla operating in 2003.** The advisory dates development to late 2003 and the first operations to shortly after early 2004; ATT&CK dates victims from 2004 [76][78].
- **Overstated: the precision of ids on 2003 events.** Every ATT&CK, CAPEC and CWE id is retrospective; NVD gives a specific CWE for only two of the eight 2003-era CVEs this study checked [18][24][73][74].
- **Understated: quiet intrusions.** The GNU FTP compromise went unannounced from March to August, and the sources opened here give no general account of targeted intrusions in 2003 [1].
- **Understated: defender cost.** CERT recorded hosts that could not stay online long enough to patch, but no primary opened puts a figure on remediation [1].
- **Understated: the weak-password problem.** CA-2003-08's compromises and the Acxiom case did their damage without any exploit [1][55].
- **Understated: the defender's tools as attack surface.** Snort and OpenSSL both carried remotely exploitable flaws [1].
- **Understated: the paths around the firewall.** In Poulsen's account the Davis-Besse firewall blocked Slammer's port and was bypassed (Reported [37]).
- **Understated: the year's international policy.** WSIS, UN resolution 58/199, ETS 189 and the UK's PECR all date from 2003, and the dated record gives each a single row against many for the worms [66][65][64][63].

### Discrepancies in the record

- **Sobig's first date.** F-Secure says the first variant was found in the wild on 9 January; Microsoft says it was detected on 10 January [31][15].
- **Blaster B's reach.** The arrest release says at least 7,000 computers; the sentencing release gives the government's later figure of more than 48,000 [44][45].
- **OpenSSH affected versions.** CA-2003-24 says before 3.7.1; CVE-2003-0693 says before 3.7 [1][29].
- **CA-2003-25.** SEI's compilation prints the CA-2003-26 text under the CA-2003-25 heading [1].
- **The Lowe's dates.** The indictment was returned on 19 November; the release is dated 9 December [50].
- **Titan Rain's first sighting.** TIME says Carpenter first saw the ring in a September 2003 Lockheed Martin break-in, and on a later page dates his first Titan Rain discoveries to March 2004 [84][86].
- **Snake's dates.** AA23-129A says development began in late 2003; ATT&CK's S0022 says initial development in 2003; ATT&CK's G0010 dates Turla's victims from 2004 [76][77][78].
- **MS03-040.** It was published on 3 October, outside the 15 October batch that began the monthly cycle [10].

## Sources

All sources were opened on 12 November 2026 or 13 November 2026, as listed, and checked as of 13 November 2026. Grade is the source's evidence grade as used in this study.

| # | Source | URL | Opened | Grade |
|---|---|---|---|---|
| 1 | CMU SEI, "2003 CERT Advisories" (compilation, CA-2003-01 to CA-2003-28) | https://www.sei.cmu.edu/documents/510/2003_019_001_496200.pdf | 2026-11-12, 2026-11-13 | Confirmed |
| 2 | CMU SEI, "2003 CERT Incident Notes" (compilation, IN-2003-01 to IN-2003-04) | https://www.sei.cmu.edu/documents/524/2003_019_001_496474.pdf | 2026-11-12, 2026-11-13 | Confirmed |
| 3 | CERT/CC, VU#484891 | https://kb.cert.org/vuls/id/484891 | 2026-11-13 | Confirmed |
| 4 | CERT/CC, VU#568148 | https://kb.cert.org/vuls/id/568148 | 2026-11-13 | Confirmed |
| 5 | Microsoft Security Bulletin MS02-039 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2002/ms02-039 | 2026-11-12, 2026-11-13 | Confirmed |
| 6 | Microsoft Security Bulletin MS03-001 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2003/ms03-001 | 2026-11-13 | Confirmed |
| 7 | Microsoft Security Bulletin MS03-007 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2003/ms03-007 | 2026-11-12, 2026-11-13 | Confirmed |
| 8 | Microsoft Security Bulletin MS03-026 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2003/ms03-026 | 2026-11-12, 2026-11-13 | Confirmed |
| 9 | Microsoft Security Bulletin MS03-039 (with the CVE-2003-0528 records) | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2003/ms03-039 | 2026-11-12, 2026-11-13 | Confirmed |
| 10 | Microsoft Security Bulletin MS03-041 (with the MS03-040 to MS03-045 publication dates) | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2003/ms03-041 | 2026-11-13 | Confirmed |
| 11 | Microsoft Security Bulletin MS03-043 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2003/ms03-043 | 2026-11-13 | Confirmed |
| 12 | Microsoft Security Bulletin MS03-049 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2003/ms03-049 | 2026-11-13 | Confirmed |
| 13 | Microsoft Security Bulletin MS03-051 (and the absent MS03-052) | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2003/ms03-051 | 2026-11-13 | Confirmed |
| 14 | Microsoft, "Microsoft Outlines New Initiatives in Ongoing Security Efforts to Help Customers", 9 October 2003 | https://news.microsoft.com/source/2003/10/09/microsoft-outlines-new-initiatives-in-ongoing-security-efforts-to-help-customers/ | 2026-11-13 | Confirmed |
| 15 | Microsoft, "Microsoft Announces Anti-Virus Reward Program", 5 November 2003 | https://news.microsoft.com/source/2003/11/05/microsoft-announces-anti-virus-reward-program/ | 2026-11-12, 2026-11-13 | Confirmed |
| 16 | Microsoft, statement on the US Attorney's arrest in the Blaster attack, 29 August 2003 | https://news.microsoft.com/source/2003/08/29/microsoft-statement-on-u-s-attorney-arrest-in-blaster-virus-attack/ | 2026-11-13 | Confirmed |
| 17 | Microsoft Lifecycle, Windows Server 2003 | https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2003- | 2026-11-13 | Confirmed |
| 18 | NVD API, CVE-2002-0649 | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2002-0649 | 2026-11-12, 2026-11-13 | Confirmed |
| 19 | CVE Services API, CVE-2002-0649 | https://cveawg.mitre.org/api/cve/CVE-2002-0649 | 2026-11-13 | Confirmed |
| 20 | NVD API, CVE-2003-0109 | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2003-0109 | 2026-11-12, 2026-11-13 | Confirmed |
| 21 | NVD API, CVE-2003-0352 | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2003-0352 | 2026-11-12, 2026-11-13 | Confirmed |
| 22 | CVE Services API, CVE-2003-0352 | https://cveawg.mitre.org/api/cve/CVE-2003-0352 | 2026-11-13 | Confirmed |
| 23 | NVD API, CVE-2003-0209 | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2003-0209 | 2026-11-13 | Confirmed |
| 24 | NVD API, CVE-2003-0545 | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2003-0545 | 2026-11-13 | Confirmed |
| 25 | CVE Services API, CVE-2002-1337 | https://cveawg.mitre.org/api/cve/CVE-2002-1337 | 2026-11-13 | Confirmed |
| 26 | CVE Services API, CVE-2003-0161 | https://cveawg.mitre.org/api/cve/CVE-2003-0161 | 2026-11-13 | Confirmed |
| 27 | CVE Services API, CVE-2003-0567 | https://cveawg.mitre.org/api/cve/CVE-2003-0567 | 2026-11-13 | Confirmed |
| 28 | CVE Services API, CVE-2003-0605 | https://cveawg.mitre.org/api/cve/CVE-2003-0605 | 2026-11-13 | Confirmed |
| 29 | CVE Services API, CVE-2003-0693 | https://cveawg.mitre.org/api/cve/CVE-2003-0693 | 2026-11-13 | Confirmed |
| 30 | CAIDA, "The Spread of the Sapphire/Slammer Worm" | https://www.caida.org/catalog/papers/2003_sapphire/ | 2026-11-12, 2026-11-13 | Confirmed; Reported (the relayed impacts) |
| 31 | F-Secure, Sobig description | https://www.f-secure.com/v-descs/sobig | 2026-11-12 | Reported |
| 32 | F-Secure, Fizzer description | https://www.f-secure.com/v-descs/fizzer | 2026-11-12 | Reported |
| 33 | F-Secure, Welchi (Welchia, Nachi) description | https://www.f-secure.com/v-descs/welchi | 2026-11-12 | Reported |
| 34 | F-Secure, Swen description | https://www.f-secure.com/v-descs/swen | 2026-11-12 | Reported |
| 35 | US-Canada Power System Outage Task Force, final report on the 14 August 2003 blackout, April 2004 (PDF) | https://www.energy.gov/sites/default/files/oeprod/DocumentsandMedia/BlackoutFinal-Web.pdf | 2026-11-12 | Confirmed |
| 36 | US Department of Energy, "Blackout 2003: Final Report on the August 14, 2003 Blackout in the United States and Canada" (report page) | https://www.energy.gov/oe/articles/blackout-2003-final-report-august-14-2003-blackout-united-states-and-canada-causes-and | 2026-11-12 | Confirmed |
| 37 | Kevin Poulsen (SecurityFocus), "Slammer worm crashed Ohio nuke plant net", The Register, 20 August 2003 | https://www.theregister.com/security/2003/08/20/slammer-worm-crashed-ohio-nuke-plant-net/1487486 | 2026-11-12 | Reported |
| 38 | Debian, investigation report on the November 2003 compromise, 2 December 2003 | https://chronicles.debian.org/www/News/2003/20031202 | 2026-11-12 | Confirmed |
| 39 | US Department of Justice, Zezev sentenced | https://www.justice.gov/archive/criminal/cybercrime/press-releases/2003/zezevSent.htm | 2026-11-12 | Confirmed |
| 40 | US Department of Justice, Amato charged | https://www.justice.gov/archive/criminal/cybercrime/press-releases/2003/amatoCharged.htm | 2026-11-12 | Confirmed (allegations) |
| 41 | US Department of Justice, Racine plea agreement | https://www.justice.gov/archive/criminal/cybercrime/press-releases/2003/racinePlea.htm | 2026-11-12 | Confirmed |
| 42 | US Department of Justice, Jiang plea, 11 July 2003 | https://www.justice.gov/archive/criminal/cybercrime/press-releases/2003/jiangPlea.htm | 2026-11-12 | Confirmed |
| 43 | US Department of Justice, Ivanov sentenced, 25 July 2003 | https://www.justice.gov/archive/criminal/cybercrime/press-releases/2003/ivanovSent.htm | 2026-11-12, 2026-11-13 | Confirmed |
| 44 | US Department of Justice, Parson arrested, 29 August 2003 | https://www.justice.gov/archive/criminal/cybercrime/press-releases/2003/parsonArrest.htm | 2026-11-12, 2026-11-13 | Confirmed |
| 45 | US Department of Justice, Parson sentenced, 28 January 2005 | https://www.justice.gov/archive/criminal/cybercrime/press-releases/2005/parsonSent.htm | 2026-11-12, 2026-11-13 | Confirmed |
| 46 | US Department of Justice, Lamo charged, 9 September 2003 | https://www.justice.gov/archive/criminal/cybercrime/press-releases/2003/lamoCharge.htm | 2026-11-12 | Confirmed |
| 47 | US Department of Justice, Carlson arrested | https://www.justice.gov/archive/criminal/cybercrime/press-releases/2003/carlsonArrest.htm | 2026-11-12 | Confirmed (allegations) |
| 48 | US Department of Justice, juvenile arrested for the RPCSDBOT variant, 26 September 2003 | https://www.justice.gov/archive/criminal/cybercrime/press-releases/2003/juvenileArrest.htm | 2026-11-12 | Confirmed |
| 49 | US Department of Justice, O'Keefe indicted, 29 September 2003 | https://www.justice.gov/archive/criminal/cybercrime/press-releases/2003/okeefeArrest.htm | 2026-11-12 | Confirmed (allegations) |
| 50 | US Department of Justice, Salcedo, Botbyl and Timmins indicted, 9 December 2003 | https://www.justice.gov/archive/criminal/cybercrime/press-releases/2003/salcedoIndict.htm | 2026-11-12 | Confirmed (allegations) |
| 51 | US Department of Justice, Salcedo sentenced, 15 December 2004 | https://www.justice.gov/archive/criminal/cybercrime/press-releases/2004/salcedoSent.htm | 2026-11-12 | Confirmed |
| 52 | US Department of Justice (C.D. Cal.), Operation Cyber Sweep cases, 20 November 2003 | https://www.justice.gov/archive/criminal/cybercrime/press-releases/2003/ramirezArrest.htm | 2026-11-12 | Confirmed |
| 53 | US Department of Justice, Operation Cyber Sweep announcement, 20 November 2003 | https://www.justice.gov/archive/opa/pr/2003/November/03_crm_638.htm | 2026-11-13 | Confirmed |
| 54 | US Department of Justice, press releases index, November 2003 | https://www.justice.gov/archive/opa/pr/2003/November/ | 2026-11-13 | Confirmed (title only) |
| 55 | US Department of Justice, Baas plea, 18 December 2003 | https://www.justice.gov/archive/criminal/cybercrime/press-releases/2003/baasPlea.htm | 2026-11-12 | Confirmed |
| 56 | US Attorney's Office, Central District of California, Operation Cyberslam indictment release, 2 October 2008 | https://www.justice.gov/archive/usao/cac/Pressroom/pr2008/135.html | 2026-11-12, 2026-11-13 | Confirmed |
| 57 | US Secret Service, "Operation Firewall nets 28 arrests", October 2004 | https://secretservice.gov/press/releases/2004/10/us-secret-services-operation-firewall-nets-28-arrests-international | 2026-11-12, 2026-11-13 | Confirmed |
| 58 | The National Strategy to Secure Cyberspace, February 2003 | https://www.cisa.gov/sites/default/files/publications/cyberspace_strategy.pdf | 2026-11-12, 2026-11-13 | Confirmed |
| 59 | The White House, HSPD-7, 17 December 2003 | https://georgewbush-whitehouse.archives.gov/news/releases/2003/12/20031217-5.html | 2026-11-12 | Confirmed |
| 60 | Pub. L. 108-187, CAN-SPAM Act of 2003 (enrolled text) | https://www.govinfo.gov/content/pkg/PLAW-108publ187/html/PLAW-108publ187.htm | 2026-11-12, 2026-11-13 | Confirmed |
| 61 | Pub. L. 108-159, Fair and Accurate Credit Transactions Act of 2003 (enrolled text) | https://www.govinfo.gov/content/pkg/PLAW-108publ159/html/PLAW-108publ159.htm | 2026-11-12 | Confirmed |
| 62 | California SB 1386, chaptered text (Chapter 915, Statutes of 2002) | http://www.leginfo.ca.gov/pub/01-02/bill/sen/sb_1351-1400/sb_1386_bill_20020926_chaptered.html | 2026-11-13 | Confirmed |
| 63 | UK SI 2003/2426, Privacy and Electronic Communications (EC Directive) Regulations 2003 | https://www.legislation.gov.uk/uksi/2003/2426/made | 2026-11-12 | Confirmed |
| 64 | Council of Europe, Additional Protocol to the Convention on Cybercrime (ETS 189) | https://rm.coe.int/168008160f | 2026-11-12 | Confirmed |
| 65 | UN General Assembly, A/RES/58/199 (ITU copy) | https://www.itu.int/ITU-D/cyb/cybersecurity/docs/UN_resolution_58_199.pdf | 2026-11-12 | Confirmed |
| 66 | WSIS, Geneva Declaration of Principles (WSIS-03/GENEVA/DOC/4-E) | https://www.itu.int/net/wsis/docs/geneva/official/dop.html | 2026-11-12 | Confirmed |
| 67 | NIST, SP 800-42 | https://csrc.nist.gov/pubs/sp/800/42/final | 2026-11-12, 2026-11-13 | Confirmed |
| 68 | NIST, SP 800-50 | https://csrc.nist.gov/pubs/sp/800/50/final | 2026-11-12, 2026-11-13 | Confirmed |
| 69 | NIST, SP 800-61 | https://csrc.nist.gov/pubs/sp/800/61/final | 2026-11-12, 2026-11-13 | Confirmed |
| 70 | NIST, FIPS 199 | https://csrc.nist.gov/pubs/fips/199/final | 2026-11-13 | Confirmed |
| 71 | NIST, SP 800-53 (original) | https://csrc.nist.gov/pubs/sp/800/53/final | 2026-11-13 | Confirmed |
| 72 | RFC 3546, Transport Layer Security (TLS) Extensions | https://www.rfc-editor.org/rfc/rfc3546.txt | 2026-11-13 | Confirmed |
| 73 | MITRE CWE, history | https://cwe.mitre.org/about/history.html | 2026-11-13 | Confirmed |
| 74 | MITRE CAPEC, about | https://capec.mitre.org/about/index.html | 2026-11-13 | Confirmed |
| 75 | FIRST, CVSS v1 archive | https://www.first.org/cvss/v1/ | 2026-11-13 | Confirmed; Inferred (the retrospective reading) |
| 76 | CISA, FBI, NSA and partners, AA23-129A, Hunting Russian Intelligence "Snake" Malware, 9 May 2023 | https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-129a | 2026-11-12 | Confirmed |
| 77 | MITRE ATT&CK, Uroburos (S0022) | https://attack.mitre.org/software/S0022/ | 2026-11-12 | Confirmed |
| 78 | MITRE ATT&CK, Turla (G0010) | https://attack.mitre.org/groups/G0010/ | 2026-11-12 | Confirmed |
| 79 | Kaspersky GReAT, "Regin: nation-state ownage of GSM networks", Securelist, 24 November 2014 | https://securelist.com/regin-nation-state-ownage-of-gsm-networks/67741/ | 2026-11-12 | Confirmed; Reported (the attribution judgement) |
| 80 | MITRE ATT&CK, Regin (S0019) | https://attack.mitre.org/software/S0019/ | 2026-11-12 | Confirmed |
| 81 | Kaspersky, "Equation group: questions and answers", v1.5, February 2015 | https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08064459/Equation_group_questions_and_answers.pdf | 2026-11-12 | Confirmed; Reported (the Equation and Regin comparison) |
| 82 | MITRE ATT&CK, Equation (G0020) | https://attack.mitre.org/groups/G0020/ | 2026-11-12 | Confirmed |
| 83 | Kaspersky GReAT and King's College London, "Penquin's Moonlit Maze", Securelist, 3 April 2017 | https://securelist.com/penquins-moonlit-maze/77883/ | 2026-11-12 | Reported |
| 84 | TIME, "The Invasion of the Chinese Cyberspies", 29 August 2005, page 1 | https://content.time.com/time/subscriber/article/0,33009,1098961,00.html | 2026-11-12 | Reported |
| 85 | TIME, the same article, page 2 | https://content.time.com/time/subscriber/article/0,33009,1098961-2,00.html | 2026-11-12 | Reported |
| 86 | TIME, the same article, page 3 | https://content.time.com/time/subscriber/article/0,33009,1098961-3,00.html | 2026-11-12 | Reported |
| 87 | TIME, "Inside the Chinese Hack Attack", 25 August 2005 | https://content.time.com/time/nation/article/0,8599,1098371,00.html | 2026-11-12 | Reported |
| 88 | The New York Times, "U.S. Debates Cyberwarfare Rules", 1 August 2009 | https://www.nytimes.com/2009/08/02/us/politics/02cyber.html | 2026-11-12 | Reported |
| 89 | TeamStarWolf library, `data/attack/` (`groups.jsonl`, `software.jsonl`) | https://github.com/TeamStarWolf/TeamStarWolf/tree/main/data/attack | 2026-11-12, 2026-11-13 | Demonstrated |
| 90 | TeamStarWolf library, `data/attack/technique_profiles.jsonl` | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/attack/technique_profiles.jsonl | 2026-11-12, 2026-11-13 | Demonstrated |
| 91 | TeamStarWolf library, `data/attack/ics/technique_profiles.jsonl` | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/attack/ics/technique_profiles.jsonl | 2026-11-12, 2026-11-13 | Demonstrated |
| 92 | TeamStarWolf library, `mitre/techniques/T1562-001.md` and `data/attack/superseded_by.jsonl` | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/mitre/techniques/T1562-001.md | 2026-11-12, 2026-11-13 | Demonstrated |
| 93 | TeamStarWolf library, `mitre/` page tree (techniques, groups, software, CAPEC, D3FEND and mitigation pages) | https://github.com/TeamStarWolf/TeamStarWolf/tree/main/mitre | 2026-11-12, 2026-11-13 | Demonstrated |
| 94 | TeamStarWolf library, `data/attack/d3fend_countermeasures.jsonl` | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/attack/d3fend_countermeasures.jsonl | 2026-11-13 | Demonstrated |
| 95 | TeamStarWolf library, `data/weaknesses/cwe.jsonl` and `data/weaknesses/capec.jsonl` | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/weaknesses/cwe.jsonl | 2026-11-13 | Demonstrated |
| 96 | TeamStarWolf library, `case-studies/` (the Russia, United States and China studies' 2003 entries; the other-states and hacker-and-the-state studies' Regin mentions; the NSA and CIA tool-leaks study's Equation coverage) | https://github.com/TeamStarWolf/TeamStarWolf/tree/main/case-studies | 2026-11-12, 2026-11-13 | Demonstrated |
| 97 | TeamStarWolf library, `case-studies/DOTCOM_ERA_CYBER_EVENTS.md` (home study and its MITRE table) | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/case-studies/DOTCOM_ERA_CYBER_EVENTS.md | 2026-11-12, 2026-11-13 | Demonstrated |
| 98 | TeamStarWolf library, `case-studies/CYBERCRIME_FOUR_BOOKS.md` (home study) | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/case-studies/CYBERCRIME_FOUR_BOOKS.md | 2026-11-13 | Demonstrated |
| 99 | TeamStarWolf library, `navigator/library-layers/chronicle-2016.json` (layer format and scoring scale) | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/chronicle-2016.json | 2026-11-13 | Demonstrated |

*© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.*

*© The MITRE Corporation. Includes material from the Common Weakness Enumeration (CWE™), used under the CWE Terms of Use. https://cwe.mitre.org/*

*© The MITRE Corporation. Includes material from the Common Attack Pattern Enumeration and Classification (CAPEC™), used under the CAPEC Terms of Use. https://capec.mitre.org/*

*© The MITRE Corporation. Includes material from MITRE D3FEND™, used under the D3FEND Terms of Use. https://d3fend.mitre.org/*

*The terms for every MITRE dataset used here are recorded in [THIRD_PARTY_NOTICES.md](/THIRD_PARTY_NOTICES.md).*

## Related references

- [Notable Incidents](/NOTABLE_INCIDENTS.md), [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [CVE Reference](/CVE_REFERENCE.md)
- [CWE Reference](/CWE_REFERENCE.md), [CAPEC Reference](/CAPEC_REFERENCE.md), [D3FEND Reference](/D3FEND_REFERENCE.md), [Supply Chain Security](/SUPPLY_CHAIN_SECURITY.md), [Incident Response](/INCIDENT_RESPONSE_REFERENCE.md), [Vulnerability Root Causes](/VULNERABILITY_ROOT_CAUSES.md), [ICS/OT Security](/ICS_OT_SECURITY_REFERENCE.md), [ICS ATT&CK Atlas](/ICS_ATTACK_ATLAS.md)
- Home studies: [The Dot-Com Era](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md); [Four Books on Cybercrime](/case-studies/CYBERCRIME_FOUR_BOOKS.md); [Kevin Mitnick](/case-studies/MITNICK_INTRUSIONS.md); [Russia-attributed actors](/case-studies/THREAT_ACTORS_RUSSIA.md); [United States actors](/case-studies/THREAT_ACTORS_UNITED_STATES.md); [Other states](/case-studies/THREAT_ACTORS_OTHER_STATES.md); [The hacker and the state](/case-studies/HACKER_AND_THE_STATE_CASES.md); [NSA and CIA tool leaks](/case-studies/NSA_CIA_TOOL_LEAKS.md); [China-attributed actors](/case-studies/THREAT_ACTORS_CHINA.md); [The Zero-Day Market](/case-studies/ZERO_DAY_MARKET_EVENTS.md); [E-Commerce Threats](/case-studies/ECOMMERCE_THREATS.md); [Change Healthcare](/case-studies/CHANGE_HEALTHCARE_2024.md); [The Year 2000 in Intrusions](/case-studies/CHRONICLE_2000.md) (Zezev); [The Year 2002 in Intrusions](/case-studies/CHRONICLE_2002.md) (Lamo, Jiang); [APT41](/case-studies/APT41_PUBLIC_RECORD.md); [Stuxnet](/case-studies/STUXNET.md); [ICS attacks and advisories](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md); [Log4Shell](/case-studies/LOG4SHELL.md); [npm supply-chain attacks](/case-studies/NPM_SUPPLY_CHAIN_ATTACKS.md); [xz Utils backdoor](/case-studies/XZ_UTILS_BACKDOOR_2024.md); [Hugging Face supply chain](/case-studies/HUGGING_FACE_SUPPLY_CHAIN.md); [SolarWinds SUNBURST](/case-studies/SOLARWINDS_SUNBURST.md)
- Series: [1993](/case-studies/CHRONICLE_1993.md), [1994](/case-studies/CHRONICLE_1994.md), [1995](/case-studies/CHRONICLE_1995.md), [1996](/case-studies/CHRONICLE_1996.md), [1997](/case-studies/CHRONICLE_1997.md), [1998](/case-studies/CHRONICLE_1998.md), [1999](/case-studies/CHRONICLE_1999.md), [2000](/case-studies/CHRONICLE_2000.md), [2001](/case-studies/CHRONICLE_2001.md), [2002](/case-studies/CHRONICLE_2002.md), [2016](/case-studies/CHRONICLE_2016.md), [2017](/case-studies/CHRONICLE_2017.md), [2018](/case-studies/CHRONICLE_2018.md), [2019](/case-studies/CHRONICLE_2019.md), [2020](/case-studies/CHRONICLE_2020.md), [2021](/case-studies/CHRONICLE_2021.md), [2022](/case-studies/CHRONICLE_2022.md), [2023](/case-studies/CHRONICLE_2023.md), [2024](/case-studies/CHRONICLE_2024.md), [2025](/case-studies/CHRONICLE_2025.md), [2026](/case-studies/CHRONICLE_2026.md)
- Techniques: [T1190 Exploit Public-Facing Application](/mitre/techniques/T1190.md), [T1210 Exploitation of Remote Services](/mitre/techniques/T1210.md), [T1046 Network Service Discovery](/mitre/techniques/T1046.md), [T1078.001 Default Accounts](/mitre/techniques/T1078-001.md), [T1110.001 Password Guessing](/mitre/techniques/T1110-001.md), [T1021.002 SMB/Windows Admin Shares](/mitre/techniques/T1021-002.md), [T1071 Application Layer Protocol](/mitre/techniques/T1071.md), [T1584.005 Botnet](/mitre/techniques/T1584-005.md), [T1498 Network Denial of Service](/mitre/techniques/T1498.md), [T1498.001 Direct Network Flood](/mitre/techniques/T1498-001.md), [T1499.001 OS Exhaustion Flood](/mitre/techniques/T1499-001.md), [T1105 Ingress Tool Transfer](/mitre/techniques/T1105.md), [T1547.001 Registry Run Keys / Startup Folder](/mitre/techniques/T1547-001.md), [T1059.003 Windows Command Shell](/mitre/techniques/T1059-003.md), [T1571 Non-Standard Port](/mitre/techniques/T1571.md), [T1566.001 Spearphishing Attachment](/mitre/techniques/T1566-001.md), [T1204.002 Malicious File](/mitre/techniques/T1204-002.md), [T1203 Exploitation for Client Execution](/mitre/techniques/T1203.md), [T1685 Disable or Modify Tools](/mitre/techniques/T1685.md), [T1684.002 Email Spoofing](/mitre/techniques/T1684-002.md), [T1584.001 Domains](/mitre/techniques/T1584-001.md), [T1684.001 Impersonation](/mitre/techniques/T1684-001.md), [T1114 Email Collection](/mitre/techniques/T1114.md), [T1499 Endpoint Denial of Service](/mitre/techniques/T1499.md), [T1078 Valid Accounts](/mitre/techniques/T1078.md), [T1068 Exploitation for Privilege Escalation](/mitre/techniques/T1068.md), [T1014 Rootkit](/mitre/techniques/T1014.md), [T1110.002 Password Cracking](/mitre/techniques/T1110-002.md), [T1213 Data from Information Repositories](/mitre/techniques/T1213.md), [T1056.001 Keylogging](/mitre/techniques/T1056-001.md), [T1669 Wi-Fi Networks](/mitre/techniques/T1669.md), [T1056 Input Capture](/mitre/techniques/T1056.md), [T1485 Data Destruction](/mitre/techniques/T1485.md), [T1199 Trusted Relationship](/mitre/techniques/T1199.md), [T1657 Financial Theft](/mitre/techniques/T1657.md); Regin and Equation techniques [T1564.005](/mitre/techniques/T1564-005.md), [T1564.004](/mitre/techniques/T1564-004.md), [T1095](/mitre/techniques/T1095.md), [T1090.002](/mitre/techniques/T1090-002.md), [T1120](/mitre/techniques/T1120.md), [T1480.001](/mitre/techniques/T1480-001.md), [T1542.002](/mitre/techniques/T1542-002.md)
- CAPEC: [CAPEC-49](/mitre/capec/CAPEC-49.md), [CAPEC-70](/mitre/capec/CAPEC-70.md), [CAPEC-100](/mitre/capec/CAPEC-100.md), [CAPEC-125](/mitre/capec/CAPEC-125.md), [CAPEC-186](/mitre/capec/CAPEC-186.md), [CAPEC-270](/mitre/capec/CAPEC-270.md), [CAPEC-300](/mitre/capec/CAPEC-300.md), [CAPEC-482](/mitre/capec/CAPEC-482.md), [CAPEC-561](/mitre/capec/CAPEC-561.md), [CAPEC-568](/mitre/capec/CAPEC-568.md)
- Groups and software: Uroburos [S0022](/mitre/software/S0022.md) and Turla [G0010](/mitre/groups/G0010.md), for Snake's late-2003 development; Regin [S0019](/mitre/software/S0019.md), with timestamps back to 2003; Equation [G0020](/mitre/groups/G0020.md), for EQUATIONDRUG from 2003
- [Navigator layers](/navigator/index.md), including this study's layers, [chronicle-2003.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/chronicle-2003.json) and [chronicle-2003-ics.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/case-studies/chronicle-2003-ics.json)
