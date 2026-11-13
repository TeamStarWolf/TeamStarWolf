# The Year 2004 in Intrusions: A Dated Record

*A TeamStarWolf case study. Published 13 November 2026; every source checked as of that date.*

[All case studies](/case-studies/README.md) · Related: [Notable Incidents](/NOTABLE_INCIDENTS.md), [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [CVE Reference](/CVE_REFERENCE.md), [Email Security](/EMAIL_SECURITY_REFERENCE.md), [Wireless Security](/WIRELESS_SECURITY_REFERENCE.md), [Cryptography](/CRYPTOGRAPHY_REFERENCE.md), [Incident Response](/INCIDENT_RESPONSE_REFERENCE.md) · Home studies for events summarized here: [Four Books on Cybercrime](/case-studies/CYBERCRIME_FOUR_BOOKS.md) (Shadowcrew and Operation Firewall, the bookmaker extortion, the Echouafni indictment), [The Dot-Com Era: Cyber Events, 1994 to 2003](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) (CAN-SPAM, Microsoft's SDL), [Russia-attributed actors](/case-studies/THREAT_ACTORS_RUSSIA.md) (Snake, Turla, APT28), [China-attributed actors](/case-studies/THREAT_ACTORS_CHINA.md) (APT1), [United States actors](/case-studies/THREAT_ACTORS_UNITED_STATES.md) (Equation, Regin), [Other states](/case-studies/THREAT_ACTORS_OTHER_STATES.md) (Darkhotel) · Series: [The Year 2001 in Intrusions](/case-studies/CHRONICLE_2001.md), [The Year 2002 in Intrusions](/case-studies/CHRONICLE_2002.md), [The Year 2016 in Intrusions](/case-studies/CHRONICLE_2016.md) and the other years in the [case studies index](/case-studies/README.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Threat intelligence analysts, security historians, email and endpoint defenders and anyone who wants the history behind current threats

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Beginner to intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 64 min (14,738 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want a dated record of the intrusions of 2004, you need the year's mass mailers, Witty, Sasser and the browser attacks side by side with the later records that date Snake, APT1 and Equation to 2004, the year's prosecutions and the new identity theft law, or you want the defender lessons that still apply

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [Part 3: the worms, the mass mailers and the web](#part-3-the-worms-the-mass-mailers-and-the-web), [Part 7: the defender view](#part-7-the-defender-view)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Notable Incidents](/NOTABLE_INCIDENTS.md), [Four Books on Cybercrime](/case-studies/CYBERCRIME_FOUR_BOOKS.md), [Email Security](/EMAIL_SECURITY_REFERENCE.md), [The Year 2002 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2002.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive summary

People who ran Windows networks or answered a help desk in 2004 spent the year inside a mail storm. Bagle was first discovered on 18 January, and on 27 January CERT/CC warned that Bagle and Novarg (MyDoom) had hit a significant number of home users and sites in a single week (Confirmed [34][1]). MyDoom.B followed on 28 January and set off the first alert of the Department of Homeland Security's new cyber alert system; Microsoft offered $250,000 for its authors the next day (Confirmed [32][33]). Netsky, launched on 16 February, ran to 28 variants, and in March US-CERT was tracking Phatbot, Beagle, Netsky and MyDoom together against home users on cable and DSL lines (Confirmed [41][36]). Then the network worms returned. Witty began at about 20:45 PST on 19 March, the day after its flaw was announced, and wrote data to random places on the disks of machines running ISS security software (Confirmed [37]). Sasser went through the LSASS flaw that MS04-011 had fixed on 13 April, and German police arrested its alleged author on 7 May, within seven days of launch, after informants came forward through Microsoft's reward program (Confirmed [9][41]; launch date Inferred).

The web became an infection path in June. Download.Ject used compromised IIS 5.0 servers to push code into the browsers of their visitors through an Internet Explorer flaw that had no patch until 30 July (Confirmed [44][16][18]). The browser flaws behind Download.Ject and the November Bofra attacks were both being exploited when Microsoft's fixes came out (Confirmed [18][25]). In December the Santy.A worm found phpBB forums through search-engine queries and defaced them (Confirmed [28]).

Law enforcement had a busy year. The CAN-SPAM Act took effect on 1 January and produced its first criminal charges on 29 April (Confirmed [56][57]). Operation Fastlink (April), Operation Digital Gridlock and Operation Web Snare (August), and the Shadowcrew indictment and Operation Firewall arrests (28 October) followed (Confirmed [62][68][69][71][72]). In December a man in the Lowe's wireless card-capture case received 108 months, which DOJ said was longer than any earlier federal hacking sentence (Confirmed [74]). Congress created aggravated identity theft, HSPD-12 set a common federal ID standard, and NIST published SP 800-61, FIPS 199 and SP 800-37 (Confirmed [87][89][78][79][82]). Microsoft shipped Windows XP Service Pack 2 with the firewall on and Data Execution Prevention, and says the SDL became an integral part of how it builds software that year (Confirmed [49][50][52][54]).

Almost all of 2004's state record was published later. A nine-agency advisory of 2023 says the FSB's Snake implant was finished around early 2004 and first used shortly after (Confirmed [102]). Mandiant's 2013 report dates to 2004 both a persona it ties to APT1, which it assesses is PLA Unit 61398, and the group's first known domain (Confirmed [107]). Kaspersky records an EquationLaser installer compiled on 18 October 2004 (Confirmed [113]; activity Inferred). The press of 2005 and 2007 reported the Titan Rain intrusions and the Athens wiretaps (Reported [110][111]).

2004 has CVE records, cited at the time in the CAN- candidate form, and almost no specific CWE: NVD gives a specific CWE, CWE-119, for only one of the nine 2004-era CVE records this study checked (Confirmed [13][128][7][40][129][21][22][31]; [4] for CWE-119; the count is Inferred). CWE, CAPEC and CVSS custody all came later, and ATT&CK did not exist (Confirmed [98][99][100]). Every ATT&CK, CAPEC and D3FEND id in Part 8 is this study's later mapping. The exceptions are the objects ATT&CK itself dates to 2004 (Inferred).

This study records the year by date. It is built only from sources opened on 12 November 2026 (two NVD records on 13 November) and from checks of the library's data run on 13 November 2026, and is checked as of 13 November 2026. Seven parts cover the timeline, the vulnerability record, the worms and web attacks, the state record, crime and prosecutions, law and standards, and the defender view. An eighth part maps the record to MITRE frameworks.

### Key facts at a glance

| Field | Value |
|---|---|
| Period | 1 January to 31 December 2004, plus the records that open or close a 2004 event: the Acxiom intrusions (2002 to 2003), the Lowe's intrusion (October to November 2003), Microsoft's reward program (5 Nov 2003), the FTC's BJ's complaint (16 Jun 2005), the Athens discovery (2005), and the vendor and government reports that date state tools to 2004 (2013 to 2023) |
| CERT/CC output | Two numbered advisories, CA-2004-01 (H.323, 13 Jan) and CA-2004-02 (email-borne viruses, 27 Jan), against 28 in 2003; the series then gives way to US-CERT's National Cyber Awareness System (Confirmed [1][2]; the end of the series is Inferred) |
| US-CERT alerts cited | SA04-028A (MyDoom.B, 28 Jan) to TA04-356A (phpBB and Santy.A, 21 Dec) (Confirmed [32][28]) |
| Microsoft | Bulletins MS04-001 to MS04-045, the last two on 14 Dec; MS04-025 shipped on 30 Jul, off the monthly day (Confirmed [26][18]; the count of 45 and the off-cycle reading are Inferred) |
| Worms and mass mailers | Bagle (18 Jan); MyDoom.B (28 Jan); MyDoom's SCO flood (from 1 Feb); Netsky (16 Feb); Phatbot (tracked 19 Mar); Witty (19 Mar); Sasser (about 1 May); MyDoom.M/O (26 Jul); Bofra (Nov); Santy.A (Dec); Cabir (undated) (Confirmed [34][32][35][41][36][37][46][23][28][47]; Sasser's date Inferred) |
| Exploited at or before the fix | CAN-2004-0549 and CAN-2004-0566 (MS04-025, 30 Jul); CAN-2004-1050 (MS04-040, 1 Dec); phpBB highlight (TA04-356A, 21 Dec) (Confirmed [18][25][28]) |
| State record | Snake operations from about early 2004; APT1 persona (16 Jan, Oct) and first domain (25 Oct); EquationLaser compile time (18 Oct); Titan Rain (Mar to Oct, Reported); Athens wiretaps (mid-2004, Reported); ATT&CK dates Turla, APT28 and Darkhotel "since at least 2004" (Confirmed [102][107][113][104][105][116]; Reported [110][111]) |
| Prosecutions and operations | FBI legal technician (26 Feb); Fastlink (21 Apr); first CAN-SPAM charges (29 Apr); Hill (17 May); Tereshchuk plea (8 Jun); bookmaker arrests (20 Jul, Reported); Levine (21 Jul); Mateias (4 Aug); Digital Gridlock (25 Aug); Web Snare (26 Aug); Wallace (12 Oct); Shadowcrew and Firewall (28 Oct); Salcedo (15 Dec) (Confirmed [60][62][57][63][61][65][67][68][69][70][71][72][74]; Reported [64]) |
| Law and policy | CAN-SPAM in effect (1 Jan); GAO-04-354 (Mar); blackout final report (Apr); Identity Theft Penalty Enhancement Act (15 Jul); HSPD-12 (27 Aug); Intelligence Reform and Terrorism Prevention Act (17 Dec) (Confirmed [56][80][81][87][89][90]) |
| Standards | SP 800-61 (Jan), FIPS 199 (Feb), RFC 3704 (Mar), SP 800-37 and SP 800-67 (May), RFC 3748 and SP 800-64 Rev. 1 (Jun), IEEE 802.11i (24 Jul), RFC 3833 (Aug), the MD5 collisions paper (16 Aug), ISO/IEC 13335-1 and SP 800-72 (Nov) (Confirmed [78][79][94][82][83][93][84][92][95][97][96][85]) |
| Platform | Windows XP SP2 to manufacturing (6 Aug), Windows Firewall on and DEP; the SDL integral to Microsoft's process; Firefox 1.0 (9 Nov) (Confirmed [49][50][52][54][55]) |
| This study's MITRE binding | 22 ATT&CK Enterprise technique rows, all later mappings; no ATT&CK for ICS rows; Turla (G0010), Uroburos (S0022), APT28 (G0007), APT1 (G0006), WEBC2 (S0109), Equation (G0020) and Darkhotel (G0012) bound with their dating caveats; no 2004 worm has an ATT&CK software object; NVD's CWE-119 plus six study-class CWEs; CAPEC entries the library maps; D3FEND pairings from the library's data; one Enterprise Navigator layer (Part 8) |

### Key findings

- **The fix sometimes came after the attack.** Microsoft's MS04-025 and MS04-040 both say their flaws were publicly disclosed and already being exploited when the bulletins were issued, and US-CERT reported public exploit code and active exploitation of the June IE flaw seven weeks before its fix (Confirmed [18][25][17]; the interval is Inferred).
- **Security software was the target.** Witty infected only machines running ISS intrusion detection and prevention products, and CERT/CC warned in January that firewalls inspecting H.323 might themselves be vulnerable (Confirmed [37][38][1]).
- **The worm got a destructive payload.** CAIDA calls Witty the first widely propagated Internet worm with a destructive payload; half the infected hosts were inactive within 12 hours (Confirmed [37]).
- **Patch time to worm time was short.** Witty began the day after its flaw and fix were publicized; Sasser arrived within weeks of MS04-011 (Confirmed [37][9][41]). Against the 26 days before Blaster recorded in the [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md), the gap shrank (Inferred).
- **Websites became a delivery system.** Download.Ject turned trusted IIS servers into drive-by sources, and the FTC alleged a spyware operation installed software through an IE feature (Confirmed [44][70]).
- **Reward money and informants caught a worm author.** The Sasser arrest came within seven days of launch through Microsoft's reward program (Confirmed [41][42]).
- **Wireless was the quiet way in.** The Lowe's card-capture case, Tereshchuk's extortion mail and the FTC's later BJ's complaint all involve unsecured or poorly secured wireless networks (Confirmed [74][61][77]; the pattern is Inferred).
- **Defaults started to change.** XP SP2 turned the firewall on in almost all configurations and added DEP and an IE Local Machine Zone lockdown that US-CERT said guards against attacks such as Download.Ject (Confirmed [50][52]).
- **The state record is written in hindsight.** Snake, APT1's first persona and domain, and EquationLaser's 2004 compile time come from reports published in 2013, 2015 and 2023 (Confirmed [102][107][113]).

### Top recommendations

1. **Keep a pre-patch mitigation path.** Three 2004 browser flaws were exploited at or before the fix (Confirmed [18][25]). Microsoft's Download.Ject advice was MS04-011 for IIS and high IE security settings until the fix existed (Confirmed [44]).
2. **Patch the security tools first.** Witty's whole vulnerable population ran ISS security software (Confirmed [37]). Treat IDS, firewall and filter parsers as exposed services.
3. **Turn protections on by default.** SP2 turned the firewall on in almost all configurations and added DEP, though DEP defaulted to OptIn for system components only (Confirmed [50][52]); that defaults reached more machines than advisory text is this study's reading (Inferred).
4. **Filter mail at the gateway.** CA-2004-02 named gateway attachment filtering and quarantine, current antivirus, and not running programs of unknown origin (Confirmed [1]).
5. **Encrypt and control wireless.** IEEE 802.11i defined TKIP and CCMP as stronger than WEP in July 2004; the FTC's BJ's complaint alleged unencrypted card data and failure to block unauthorized wireless access (Confirmed [92][77]).
6. **Protect the code repository.** US-CERT warned that the CVS heap overflow could let an attacker alter repositories to include Trojan horses or backdoors (Confirmed [15]).
7. **Filter spoofed sources.** RFC 3704 extended BCP 38 ingress filtering to multihomed networks to limit spoofed-source DDoS (Confirmed [94]).
8. **Plan for long-lived sessions.** TA04-111A singled out BGP routers as exposed to TCP session resets (Confirmed [14]).

## Scope and method

This study covers intrusions, vulnerabilities, malware, prosecutions, regulation, standards and policy dated to 2004, plus the later records that open, close or explain a 2004 event. It follows the method of the [case studies collection](/case-studies/README.md): primary sources first, every claim graded, and numbers given as the source states them. Sources were opened on 12 November 2026; the library data checks were run on 13 November 2026.

| Grade | Meaning in this study |
|---|---|
| Confirmed | The primary record was opened and states the fact: a CERT/CC advisory or vulnerability note, a US-CERT alert in CISA's archive, a vendor bulletin, statement or research report stated as that vendor's own finding, a CVE or NVD record, a statute, a Justice Department, FTC, Secret Service, White House, DHS or GAO record, a NIST, IEEE, ISO, RFC Editor, Council of Europe or MITRE record, CAIDA's measurements of its own data, or a live ATT&CK page |
| Reported | Only a secondary source supports the fact: TIME on Titan Rain, IEEE Spectrum and The Intercept on the Athens wiretaps, The Register on the bookmaker arrests, and figures DOJ relays from the Anti-Phishing Working Group. The source is named in the text |
| Demonstrated | A check this study ran itself and saw the result: id, name, tactic and page checks in the library's data files and `mitre/` page tree |
| Inferred | The study's own reasoning, labelled where it appears. Every ATT&CK, CAPEC and D3FEND id bound to a 2004 event is Inferred as to the binding, and so is every CWE that NVD does not list |

Charging documents, indictments and complaints are allegations; where this study cites one, the record confirms that the allegation was made, not that it was proven.

Limits a reader should know:

- **No contemporaneous ATT&CK, CWE, CAPEC or CVSS.** MITRE began revising its CVE categorization in 2005 under NIST SAMATE and released the first CWE list in 2006; CAPEC was first released in 2007; NIAC chose FIRST as CVSS custodian on 14 April 2005 (Confirmed [98][99][100]). Years before 2015 have no contemporaneous ATT&CK mapping in this series. Where ATT&CK itself dates an object to 2004, Part 4 and Part 8 say so.
- **CAN- and CVE- ids.** Bulletins and alerts of 2004 cite candidates in the CAN- form; NVD now lists them as CVE- ids. Both forms name the same record (Confirmed [9][13]).
- **What was not checked.** No primary was opened for: MyDoom.A's first-seen date and the effect of its SCO flood; the Cisco source-code theft and the Stakkato supercomputer intrusions; the Council of Europe Convention on Cybercrime's entry into force (the Treaty Office page refused the request); a CISA alert for Sasser; vendor pages for Netsky, Santy, Phatbot and the later MyDoom variants; the AOL screen-name sale case; ChoicePoint; PCI DSS 1.0; the OWASP Top Ten of 2004; NIST SP 800-63 and SP 800-27 Rev. A; WPA2 certification; the Greek government and ADAE reports on the Vodafone wiretaps; any US government record on Titan Rain; FireEye's 2014 APT28 report; the 2014 charges against Unit 61398 officers; the full text of GAO-04-354; the total count of 2004 CVE records; and whether any 2004 CVE is in CISA's Known Exploited Vulnerabilities catalog. They are left out. Their absence here is not evidence that nothing happened.

## Part 1: the year as a dated timeline

One row per event or report. The date is the event date where the source gives one, otherwise the publication date.

| Date | Event | Thread | Sector | Grade | Sources |
|---|---|---|---|---|---|
| 2002-04 to 2003-08 (frame) | Scott Levine of Snipermail allegedly downloads about 8.2 GB from an Acxiom FTP server (indicted 21 Jul 2004) | Crime | Data services | Confirmed (as alleged) | [65][66] |
| 2003-10 (frame) | Jay Echouafni allegedly starts hiring attackers to run DDoS against competitors (charged in Web Snare, Aug 2004). Home: [Four Books on Cybercrime](/case-studies/CYBERCRIME_FOUR_BOOKS.md) | Crime | E-commerce | Confirmed (as alleged) | [69] |
| 2003-10 to 2003-11-09 (frame) | The Lowe's wireless intrusion (sentence 15 Dec 2004) | Crime | Retail | Confirmed | [74] |
| 2003-11-05 (frame) | Microsoft's $5 million Anti-Virus Reward Program with the FBI, the Secret Service and Interpol | Industry | Technology | Confirmed | [42] |
| Late 2003 (frame) | AA23-129A: the FSB begins developing Snake as "Uroburos" | Espionage | Government | Confirmed | [102] |
| 2004-01-01 | CAN-SPAM in effect, except section 9. Home: [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) | Law | Cross-sector | Confirmed | [56] |
| 2004-01 | NIST SP 800-61, Computer Security Incident Handling Guide | Standards | Government | Confirmed | [78] |
| 2004-01-13 | CA-2004-01, multiple H.323 message flaws (with NISCC); VU#749342 published | Vulnerability | Telephony, network | Confirmed | [1][3] |
| 2004-01-16 | Mandiant: the persona UglyGorilla asks on the PLA Daily's China Military Online forum whether China has cyber troops | Espionage | Government | Confirmed | [107] |
| 2004-01-18 | Bagle first discovered (F-Secure) | Worm | Cross-sector | Confirmed | [34] |
| 2004-01-23 | Compile time of the first WEBC2-KT3 sample (Mandiant) | Espionage | Unknown | Inferred | [107] |
| 2004-01-27 | CA-2004-02, email-borne viruses: Bagle and Novarg (MyDoom) | Worm | Consumers, cross-sector | Confirmed | [1] |
| 2004-01-28 | MyDoom.B detected; US-CERT SA04-028A; the first alert of DHS's new cyber alert system | Worm | Consumers, technology | Confirmed | [32][33] |
| 2004-01-29 | Microsoft offers $250,000 for the MyDoom.B authors | Industry | Technology | Confirmed | [33] |
| 2004-02 | FIPS 199, security categorization | Standards | Government | Confirmed | [79] |
| 2004-02-01 | MyDoom's scheduled flood of the SCO website begins | Worm | Technology | Confirmed | [35] |
| 2004-02-03 | Myron Tereshchuk begins extortion e-mails to MicroPatent's president | Crime | Information services | Confirmed | [61] |
| 2004-02-10 | MS04-007, ASN.1 library (CAN-2003-0818); SA04-041A | Vulnerability | Cross-sector | Confirmed | [5][6] |
| 2004-02-12 | Portions of Windows 2000 and NT 4.0 source code posted online; Microsoft says its network was not breached | Leak | Technology | Confirmed | [48] |
| 2004-02-12 | MyDoom (Novarg) programmed to stop spreading | Worm | Cross-sector | Confirmed | [35] |
| 2004-02-16 | Netsky launched, by Microsoft's account | Worm | Cross-sector | Confirmed | [41] |
| 2004-02-26 | An FBI headquarters legal technician sentenced to 12 months for unlawful access to the FBI's Automated Case Support system | Insider | Government | Confirmed | [60] |
| 2004-03 | RFC 3704 (BCP 84), ingress filtering for multihomed networks | Standards | Internet | Confirmed | [94] |
| 2004-03 | TIME: Shawn Carpenter's first Titan Rain discoveries | Espionage | Government, defense | Reported | [110] |
| 2004-03-08 | VU#947254, the ISS PAM ICQ parsing flaw, date public | Vulnerability | Security tools | Confirmed | [38] |
| 2004-03-10 | AOL, EarthLink, Microsoft and Yahoo file six CAN-SPAM lawsuits | Law | Email, ISPs | Confirmed | [59] |
| 2004-03-15 | GAO-04-354 on control-system security (released 30 Mar) | Policy | Critical infrastructure | Confirmed | [80] |
| 2004-03-18 | TA04-078A, three OpenSSL denial-of-service flaws; eEye announces the ISS PAM flaw | Vulnerability | Cross-sector; security tools | Confirmed | [8][37] |
| 2004-03-19 | SA04-079A tracks Phatbot, Beagle, Netsky and MyDoom; Witty begins at about 20:45 PST | Worm | Consumers; security tools | Confirmed | [36][37] |
| 2004-03-23 | CVE-2004-0362 record published | Vulnerability | Security tools | Confirmed | [39] |
| 2004-04 | US-Canada task force final report on the 2003 blackout | Policy | Energy | Confirmed | [81] |
| 2004-04-13 | MS04-011 (14 flaws, LSASS among them); TA04-104A; VU#753212 date public | Vulnerability | Cross-sector | Confirmed | [9][10][11] |
| 2004-04-16 | CVE-2003-0533 record published | Vulnerability | Cross-sector | Confirmed | [12] |
| 2004-04-20 | TA04-111A, TCP session reset weakness; BGP routers singled out | Vulnerability | Internet infrastructure | Confirmed | [14] |
| 2004-04-21 | Operation Fastlink searches begin (announced 22 Apr) | Crime | Software, media | Confirmed | [62] |
| 2004-04-29 | First criminal CAN-SPAM charges; the FTC's first CAN-SPAM cases | Crime | Email | Confirmed (as alleged) | [57][58] |
| About 2004-05-01 | Sasser launched | Worm | Cross-sector | Inferred | [41] |
| 2004-05 | NIST SP 800-37 and SP 800-67 | Standards | Government | Confirmed | [82][83] |
| 2004-05-07 | German police arrest the alleged Sasser author (Microsoft statement, 8 May) | Crime | Technology | Confirmed | [41] |
| 2004-05-17 | Zachary Keith Hill sentenced to 46 months for AOL and PayPal phishing (announced 18 May) | Crime | Financial services | Confirmed | [63] |
| 2004-05-26 | TA04-147A, CVS heap overflow | Vulnerability | Software development | Confirmed | [15] |
| 2004-06 | RFC 3748 (EAP) and NIST SP 800-64 Rev. 1 | Standards | Internet; government | Confirmed | [93][84] |
| 2004-06-01 | Operation Web Snare begins | Crime | Cross-sector | Confirmed | [69] |
| 2004-06-03 | VU#713878, the IE cross-domain flaw, date public (note published 9 Jun) | Vulnerability | Cross-sector | Confirmed | [16] |
| 2004-06-08 | Tereshchuk pleads guilty | Crime | Information services | Confirmed | [61] |
| 2004-06-11 | TA04-163A: exploit code public and the IE flaw actively exploited | Exploitation | Cross-sector | Confirmed | [17] |
| 2004-06-24 | Download.Ject: Microsoft responds; the origin point in Russia is shut down | Exploitation | Web hosting, consumers | Confirmed | [44] |
| 2004-06 | APWG count: 1,422 unique phishing attacks in June, up from 176 in January (as DOJ quotes it) | Phishing | Financial services | Reported | [69] |
| Mid-2004 | Rogue software in Vodafone Greece's switches begins tapping about 100 phones before the Athens Olympics | Espionage | Telecommunications | Reported | [111] |
| 2004-07-02 | SA04-184A: install IE update KB870669 against Download.Ject and Scob | Exploitation | Consumers | Confirmed | [45] |
| 2004-07-15 | Identity Theft Penalty Enhancement Act signed | Law | Cross-sector | Confirmed | [87][88] |
| 2004-07-20 | Three suspects in the bookmaker DDoS extortion arrested in Russia. Home: [Four Books on Cybercrime](/case-studies/CYBERCRIME_FOUR_BOOKS.md) | Crime | Online gambling | Reported | [64] |
| 2004-07-21 | Levine indicted on 144 counts (Acxiom) | Crime | Data services | Confirmed (as alleged) | [65][66] |
| 2004-07-24 | IEEE 802.11i published | Standards | Wireless | Confirmed | [92] |
| 2004-07-26 | SA04-208A, MyDoom.M/MyDoom.O | Worm | Consumers, search engines | Confirmed | [46] |
| 2004-07-30 | MS04-025, IE cumulative update; two of its flaws already exploited | Vulnerability | Cross-sector | Confirmed | [18] |
| 2004-08 | RFC 3833, threat analysis of the DNS | Standards | Internet | Confirmed | [95] |
| 2004-08-04 | Calin Mateias and five others indicted over Ingram Micro | Crime | Technology distribution | Confirmed (as alleged) | [67] |
| 2004-08-06 | Windows XP SP2 released to manufacturing | Industry | Technology | Confirmed | [49] |
| 2004-08-16 | Wang, Feng, Lai and Yu post MD4, MD5, HAVAL-128 and RIPEMD collisions | Cryptography | Cross-sector | Confirmed | [97] |
| 2004-08-25 | Operation Digital Gridlock, the first federal criminal action against P2P piracy | Crime | Media | Confirmed | [68] |
| 2004-08-26 | Operation Web Snare announced | Crime | Cross-sector | Confirmed | [69] |
| 2004-08-27 | HSPD-12 | Policy | Government | Confirmed | [89] |
| 2004-08-30 | SA04-243A on XP SP2's security changes | Industry | Technology | Confirmed | [50] |
| 2004-09-14 | MS04-028, GDI+ JPEG overrun | Vulnerability | Cross-sector | Confirmed | [19] |
| 2004-09-16 | TA04-260A on the JPEG flaw | Vulnerability | Cross-sector | Confirmed | [20] |
| 2004-09-17 | XP SP2 lifecycle start date | Industry | Technology | Confirmed | [51] |
| 2004-10 | Mandiant: UglyGorilla active in network operations since this month; TIME: the Army passes Carpenter to the FBI | Espionage | Government, defense | Confirmed; Reported | [107][110] |
| 2004-10-12 | FTC sues Seismic Entertainment, Smartbot.Net and Sanford Wallace over spyware | Crime | Consumers | Confirmed (as alleged) | [70] |
| 2004-10-18 | Compile time of an EquationLaser installer sample (Kaspersky) | Espionage | Unknown | Inferred | [113] |
| 2004-10-25 | hugesoft.org, the first APT1 zone Mandiant knew, registered | Espionage | Unknown | Confirmed | [107] |
| 2004-10-28 | Shadowcrew indictment and Operation Firewall arrests. Home: [Four Books on Cybercrime](/case-studies/CYBERCRIME_FOUR_BOOKS.md) | Crime | Payments | Confirmed (as alleged) | [71][72] |
| 2004-11 | ISO/IEC 13335-1:2004 and NIST SP 800-72 | Standards | Cross-sector; government | Confirmed | [96][85] |
| 2004-11-02 | VU#842160, the IE IFRAME flaw used by Bofra, date public | Exploitation | Cross-sector | Confirmed | [23] |
| 2004-11-09 | Firefox 1.0 release notes | Industry | Technology | Confirmed | [55] |
| 2004-11-10 | TA04-315A: the IFRAME flaw exploited through e-mailed links | Exploitation | Cross-sector | Confirmed | [24] |
| 2004-11-12 | CVE-2004-1315 published in NVD | Vulnerability | Web applications | Confirmed | [30][31] |
| 2004-11-19 | VU#497400, the phpBB highlight flaw, date public | Vulnerability | Web applications | Confirmed | [27] |
| 2004-11-23 | CVE-2004-0597 (libpng) published in NVD | Vulnerability | Cross-sector | Confirmed | [22] |
| 2004-12-01 | MS04-040 fixes the exploited IFRAME flaw | Vulnerability | Cross-sector | Confirmed | [25] |
| 2004-12-08 | Digital PhishNet launched | Industry | Financial services | Confirmed | [73] |
| 2004-12-14 | MS04-044 and MS04-045, the year's last bulletins | Vulnerability | Cross-sector | Confirmed | [26] |
| 2004-12-15 | Brian Salcedo sentenced to 108 months (Lowe's) | Crime | Retail | Confirmed | [74] |
| 2004-12-17 | Intelligence Reform and Terrorism Prevention Act | Law | Government | Confirmed | [90] |
| 2004-12-21 | TA04-356A: Santy.A exploits phpBB; VU#497400 published | Worm | Web applications | Confirmed | [28][27] |
| 2004-12-22 | The first Operation Fastlink defendant pleads guilty | Crime | Software | Confirmed | [75][76] |
| Early 2004 | AA23-129A: Snake's initial versions complete, with operations shortly after | Espionage | Government | Confirmed | [102] |
| 2004 | Microsoft: the SDL becomes integral to its development process; Cabir, a Bluetooth worm for Symbian phones (undated) | Industry; Worm | Technology; mobile | Confirmed | [54][47] |
| Since at least 2004 | ATT&CK: Turla victims, APT28 activity and Darkhotel targeting | Espionage | Government | Confirmed | [104][105][116] |
| 2005-01-24 to 2005-03-09 (boundary) | The Athens wiretaps found and removed | Espionage | Telecommunications | Reported | [111] |
| 2005-02 (boundary) | NIST SP 800-53, the first federal control catalog | Standards | Government | Confirmed | [86] |
| 2005-04-14 (boundary) | FIRST becomes CVSS custodian | Standards | Cross-sector | Confirmed | [100] |
| 2005-06-16 (boundary) | FTC's BJ's Wholesale Club complaint | Regulation | Retail | Confirmed (as alleged) | [77] |
| 2005-08-29 (boundary) | TIME publishes its Titan Rain account | Espionage | Government, defense | Reported | [110] |
| 2007-06-29 (boundary) | IEEE Spectrum publishes "The Athens Affair" | Espionage | Telecommunications | Reported | [111] |
| 2013-02 (boundary) | Mandiant's APT1 report | Espionage | Cross-sector | Confirmed | [107] |
| 2014-11 (boundary) | Kaspersky's Darkhotel report and Regin report (24 Nov) | Espionage | Hospitality; telecommunications | Confirmed | [117][115] |
| 2015-02 (boundary) | Kaspersky's Equation Q&A | Espionage | Unknown | Confirmed | [113] |
| 2015-09-28 (boundary) | The Intercept's account of the Athens wiretaps | Espionage | Telecommunications | Reported | [112] |
| 2016-06-16 (boundary) | SecureWorks' TG-4127 report | Espionage | Government, politics | Confirmed | [106] |
| 2023-05-09 (boundary) | AA23-129A attributes Snake to FSB Center 16 | Espionage | Government | Confirmed | [102] |

## Part 2: the vulnerability record

### CERT/CC's last two advisories

CERT/CC issued two numbered advisories in 2004, against 28 in 2003 (Confirmed [1]).

- **CA-2004-01 (13 January), multiple H.323 message flaws.** The UK's NISCC reported flaws in many vendors' implementations of H.323's H.225.0 setup messages, found with a test suite built by NISCC and the University of Oulu's OUSPG. Affected products included VoIP, video conferencing, routers and firewalls, and the impact ran from denial of service to code execution. The flaws are tracked as VU#749342 and, for Microsoft, CAN-2003-0819 (MS04-001) (Confirmed [1][3]). CERT advised patching and filtering 1720/TCP and 1720/UDP at the border. It also warned that some firewalls that inspect H.323 might themselves be vulnerable, so some sites might want to turn application-layer H.323 inspection off (Confirmed [1]). NVD describes CVE-2003-0819 as a buffer overflow in the H.323 filter of ISA Server 2000 that runs code in the Microsoft Firewall Service, and maps it to CWE-119 (Confirmed [4]).
- **CA-2004-02 (27 January), email-borne viruses.** Bagle and Novarg (MyDoom) had hit a significant number of home users and sites in the past week, CERT said. Their technology was not significantly different from Sobig and Mimail, and they spread through social engineering and human action, with attachments and peer-to-peer file sharing (Confirmed [1]). The impacts listed were address harvesting, backdoors used to download DDoS tools, attacks on other systems, and home and small-business machines used to send spam (Confirmed [1]). The defenses were current antivirus with automatic updates as the best first line of defense, not running programs of unknown origin, care with URLs in mail, a personal firewall (which a virus may disable), and attachment-extension filtering with quarantine at the gateway. The advisory defines phishing as misleading URLs that lead to spoofed sites collecting passwords or account numbers (Confirmed [1]).

SEI's collection is titled "CERT Advisories 1988-2004" and says CERT/CC advisories are now part of the US-CERT National Cyber Awareness System (Confirmed [2]). The 2004 volume holds only these two, so this study reads 2004 as the end of the numbered series (Inferred [2]). From here the dated alerts are US-CERT's SA (home user) and TA (technical) series in CISA's archive.

### Microsoft's year

Microsoft's 2004 bulletins end with MS04-044 and MS04-045, both published on 14 December, and no MS04-046 page exists, which implies 45 bulletins (Confirmed [26]; Inferred for the count). Bulletins cited here:

- **MS04-007 (10 February).** An unchecked buffer in the Microsoft ASN.1 Library (CAN-2003-0818), rated Critical on Windows NT 4.0, 2000, XP and Server 2003, giving code execution with system privileges. There was no workaround. eEye Digital Security reported it, and MBSA, Windows Update and SUS could detect the need for the update (Confirmed [5]). US-CERT's SA04-041A told home users to install it (Confirmed [6]). NVD describes multiple integer overflows in MSASN1.DLL, which LSASS.EXE, CRYPT32.DLL and other components use, and lists NVD-CWE-Other (Confirmed [7]).
- **MS04-011 (13 April).** A Critical cumulative update for 14 flaws. They include the LSASS buffer overrun CAN-2003-0533 (Critical on Windows 2000 and XP, Low on Server 2003), the PCT/SSL overrun CAN-2003-0719, Winlogon, Metafile, H.323, Negotiate SSP, an SSL denial of service and the ASN.1 double free CAN-2004-0123. Microsoft revised the bulletin on 15 June and 10 August (Confirmed [9]). Its LSASS workarounds were Internet Connection Firewall, blocking UDP 135, 137, 138 and 445 and TCP 135, 139, 445 and 593 plus unsolicited inbound traffic above 1024, and TCP/IP or IPsec filtering; for the SSL flaw, blocking 443 and 636. The bulletin text does not name Sasser (Confirmed [9]). eEye is credited for the LSASS, Metafile, Local Descriptor Table and Virtual DOS Machine flaws (Confirmed [9]). US-CERT's TA04-104A summarized the April bulletins and mapped LSASS to VU#753212 (Confirmed [10]).
- **MS04-025 (30 July).** A Critical cumulative IE update. CAN-2004-0549 and CAN-2004-0566 were publicly disclosed and being exploited when it was issued; CAN-2003-1048 was disclosed but not exploited (Confirmed [18]). It shipped on 30 July, not on the month's release day of 13 July; the bulletin itself does not call the release out-of-band (Inferred [18]).
- **MS04-028 (14 September).** A Critical buffer overrun in GDI+ JPEG processing (CAN-2004-0200), affecting Windows XP and Server 2003, IE 6 SP1, the .NET Framework, Office, Visio, Project and Visual Studio. XP SP2 was not affected by default. Microsoft said the flaw had not been publicly disclosed or reported exploited at issue, and shipped an Enterprise Update Scanning Tool and a consumer GDI+ Detection Tool; it revised the bulletin on 12 October and 14 December (Confirmed [19]). TA04-260A (16 September) warned that any software rendering JPEG through the vulnerable gdiplus.dll could be affected (Confirmed [20]). NVD describes a JPEG whose small COM field length is normalized to a large integer before a memory copy, and lists NVD-CWE-Other (Confirmed [21]).
- **MS04-040 (1 December).** A Critical IE update for CAN-2004-1050, the IFRAME flaw, which Microsoft says was publicly disclosed and being exploited when the bulletin was released (Confirmed [25]).

### LSASS: the flaw behind Sasser

CERT/CC's VU#753212 describes a buffer overflow in an Active Directory logging function exposed by the LSASS DCE/RPC interface, caused by misuse of a `vsprintf()` call, which allows remote unauthenticated code execution and complete system compromise. Its public date is 13 April and its first-published date 14 April, and it lists Windows 2000, XP and Server 2003 (Confirmed [11]). The CVE record for CVE-2003-0533 was published on 16 April and describes a stack-based buffer overflow in LSASS on Windows NT 4.0 through Server 2003; NVD's own record, published on 1 June, places it in LSASRV.DLL and lists NVD-CWE-Other (Confirmed [12][13]). Part 3 covers the worm.

### The parsers

Data formats carried several of the year's critical flaws: ASN.1 in MS04-007 and MS04-011, H.323 in CA-2004-01, JPEG in MS04-028 and PNG in libpng 1.2.5 and earlier, which NVD describes as having multiple buffer overflows reachable through malformed images (Confirmed [5][9][1][19][22]). The H.323 flaws were found with the NISCC and OUSPG test suite (Confirmed [1]). The [vulnerability root causes page](/VULNERABILITY_ROOT_CAUSES.md) places these classes in the CWE Pillars.

### Other infrastructure flaws

- **OpenSSL (March).** TA04-078A covered three OpenSSL denial-of-service flaws reported by NISCC and the OpenSSL Project, CAN-2004-0079 among them (Confirmed [8]).
- **TCP session resets (20 April).** TA04-111A warned that remote attackers could terminate persistent TCP sessions and that sustained exploitation against BGP routers could affect portions of the Internet community (Confirmed [14]).
- **CVS (26 May).** TA04-147A covered a heap overflow in CVS before 1.11.16 (CAN-2004-0396, VU#192038) and warned that repositories could be altered to include Trojan horses or backdoors (Confirmed [15]). No such alteration is recorded in the sources opened here; the [npm](/case-studies/NPM_SUPPLY_CHAIN_ATTACKS.md), [xz Utils](/case-studies/XZ_UTILS_BACKDOOR_2024.md), [Hugging Face](/case-studies/HUGGING_FACE_SUPPLY_CHAIN.md) and [SolarWinds](/case-studies/SOLARWINDS_SUNBURST.md) studies record what happens when trusted code is changed (Inferred).

### The CVE record

NVD lists NVD-CWE-Other for CVE-2003-0533, CVE-2003-0719, CVE-2003-0818, CVE-2004-0362, CVE-2004-0549, CVE-2004-0200, CVE-2004-0597 and CVE-2004-1315; of the 2004-era records checked, only CVE-2003-0819 carries a specific CWE, CWE-119 (Confirmed [13][128][7][40][129][21][22][31]; [4] for CWE-119). No CVE exists for the mass mailers themselves; their record is CERT, US-CERT and vendor descriptions (Inferred).

## Part 3: the worms, the mass mailers and the web

### MyDoom, Bagle and Netsky

- **Bagle.** F-Secure says Bagle was first discovered on 18 January. It is a mass mailer with its own SMTP engine that opens a backdoor able to download and run programs, and it was programmed to stop spreading on 28 January (Confirmed [34]).
- **MyDoom (Novarg).** F-Secure says it spreads by e-mail and through the Kazaa shared folder, installs a backdoor that can act as a proxy, was scheduled to flood the SCO website from 1 February and was programmed to stop spreading on 12 February. F-Secure's page gives no first-seen date (Confirmed [35]).
- **MyDoom.B.** US-CERT's SA04-028A (28 January, revised 30 January) reported a variant spreading through attachments and peer-to-peer sharing that may stop the computer updating anti-virus and other software, and that spoofs From addresses (Confirmed [32]). Microsoft said on 29 January that MyDoom.B blocks access to anti-virus vendor sites and microsoft.com, leaves a backdoor, and was designed to attack microsoft.com the next month. It also said the worm set off the first alert from the new DHS cyber alert system on 28 January, and it offered $250,000 for the authors (Confirmed [33]).
- **Netsky.** Microsoft says Netsky launched on 16 February, and that German authorities allege all 28 of its variants are connected to the person arrested for Sasser (Confirmed [41]).
- **Phatbot and the home-user picture.** On 19 March US-CERT's SA04-079A said it was tracking Phatbot, a remotely controlled trojan that controls large numbers of systems and spreads through unpatched Windows flaws, along with Beagle, Netsky and MyDoom. All of them were aimed at home users on cable and DSL connections (Confirmed [36]).
- **MyDoom.M/O.** SA04-208A (26 July) reported a variant that runs search-engine queries on addresses harvested from infected machines, which could slow popular search engines, and that may open a backdoor (Confirmed [46]).

No 2004 mass mailer has an ATT&CK software object in the library's data (Demonstrated [121]).

### Witty

CAIDA's analysis is the measurement record. Witty began spreading at about 20:45 PST on 19 March, the day after eEye announced the flaw in the ISS Protocol Analysis Module on 18 March (Confirmed [37]). About 110 hosts were infected in the first ten seconds, which CAIDA reads as a hitlist or preseeded hosts. The vulnerable population was about 12,000 hosts, every one running ISS security software, and the infection peaked after about 45 minutes, with traffic above 90 Gbit/s (Confirmed [37]). CAIDA calls it the first widely propagated Internet worm with a destructive payload: it wrote data to random disk locations, and half the infected hosts were inactive within 12 hours (Confirmed [37]).

CERT/CC's VU#947254 says the module, used in RealSecure, Proventia and BlackICE, has a stack buffer overflow in ICQ server-response parsing that a single spoofable UDP packet can reach, and that Witty overwrites sections of the hard drive (Confirmed [38]). The CVE-2004-0362 record, published on 23 March, covers stack-based overflows in those parsing routines (Confirmed [39]). NVD lists NVD-CWE-Other (Confirmed [40]).

### Sasser and the reward program

F-Secure describes Sasser as a self-spreading network worm that uses the MS04-011 LSASS flaw, scans random IP addresses on TCP 445, and can crash LSASS on unpatched machines with its probing. Its page gives no first-seen date (Confirmed [43]). On 8 May Microsoft said German police had arrested the alleged author within seven days of the worm's launch, in a case covering all four Sasser variants. Informants had approached Microsoft under its Anti-Virus Reward Program, $250,000 would be paid on conviction, and German police, the FBI and the Secret Service were involved (Confirmed [41]). The launch date of about 1 May is inferred from "within seven days"; no dated launch record was opened (Inferred [41]). Microsoft had announced the $5 million program on 5 November 2003 with the FBI, the Secret Service and Interpol, with its first rewards aimed at Blaster and Sobig (Confirmed [42]).

### Download.Ject, Scob and the IE flaws

CERT/CC's VU#713878 describes an IE cross-domain redirect flaw that let script run in the Local Machine Zone. Its public date is 3 June, and it reports public exploit code and incidents involving Scob, Download.Ject, Toofeer and Berbew (Confirmed [16]). US-CERT's TA04-163A said exploit code was public and that it had incident reports of active exploitation (Confirmed [17]).

On 24 June Microsoft responded to reports that enterprise IIS 5.0 servers without MS04-011 were being targeted; the attack's origin point in Russia was identified and shut down that day (Confirmed [44]). Microsoft called it a targeted manual attack, not a worm, and said it knew of no widespread customer impact. The compromised servers used the IE flaw to deliver code to their visitors, and Microsoft advised MS04-011 for IIS and high IE security settings (Confirmed [44]). On 2 July SA04-184A told users to install IE update KB870669 against Download.Ject, JS.Scob.Trojan, Scob and JS.Toofeer, whose installed software could be used to steal financial information (Confirmed [45]). MS04-025 fixed CAN-2004-0549 on 30 July (Confirmed [18][16]).

### Bofra

CERT/CC's VU#842160 (IE FRAME/IFRAME overflow, CVE-2004-1050, public 2 November) cites public reports that malicious code called Bofra, a set of MyDoom variants, uses it, and says XP SP2 is not vulnerable (Confirmed [23]). TA04-315A reported that the flaw was being exploited through links sent in e-mail by code known as MyDoom.AG, AH or AI, or Bofra (Confirmed [24]). MS04-040 fixed it on 1 December (Confirmed [25]).

### Santy

VU#497400 (phpBB highlight parameter) has a public date of 19 November and a first-published date of 21 December. It reports exploitation and says phpBB 2.0.11 did not fully fix the flaw; the full fix came in 2.0.16 (Confirmed [27]). On 21 December TA04-356A said the Santy.A worm was actively exploiting the flaw in phpBB 2.0.10 and earlier, finding targets through search-engine keyword queries and defacing web files (Confirmed [28]). The CVE-2004-1315 record names Santy.A as exploiting it (Confirmed [29]).

### Cabir

F-Secure describes Cabir as a worm for Symbian Series 60 phones that spreads over Bluetooth; the recipient must accept and install the file, and the installer shows the group initials 29A. The page gives no date (Confirmed [47]). It is in this chronicle because F-Secure's record places it in 2004 (Inferred). No ATT&CK Mobile mapping is attempted.

### No ATT&CK software objects

None of MyDoom, Novarg, Bagle, Netsky, Sasser, Witty, Santy, Cabir, Phatbot, Scob, Download.Ject or Bofra appears in the library's ATT&CK software data, so any binding for the year's worms is technique-level only (Demonstrated [121]).

## Part 4: the state record

Nothing in this part was public in 2004. Each item comes from a later government, vendor or press record, and the grade follows that record.

### Snake begins operations

The joint advisory AA23-129A (9 May 2023), from the FBI, NSA, CISA, the Cyber National Mission Force, the UK NCSC, Canada's CCCS and CSE, Australia's ACSC and New Zealand's NCSC, says the FSB began developing Snake as "Uroburos" in late 2003. Initial versions appear to have been completed around early 2004, with operations first conducted using the implant shortly after (Confirmed [102]). It attributes Snake operations to a known, unnamed unit within FSB Center 16 that also operates the wider Turla toolset. Development was historically by FSB officers in Ryazan, and operations were also launched from a Center 16 building in Moscow (Confirmed [102]). ATT&CK's [Uroburos (S0022)](/mitre/software/S0022.md) says it is used by units within the FSB and lists T1014 Rootkit for its kernel module (Confirmed [103]). ATT&CK's [Turla (G0010)](/mitre/groups/G0010.md), version 5.1, attributes the group to the FSB and says it has compromised victims in over 50 countries since at least 2004, naming no dated 2004 victim event (Confirmed [104]). The advisory's technique table describes the implant as analysed in 2023, not the 2004 build (Confirmed [102]; Part 8). The [Russia study](/case-studies/THREAT_ACTORS_RUSSIA.md) is the home.

### APT28's start date

ATT&CK's [APT28 (G0007)](/mitre/groups/G0007.md), version 5.3, attributes the group to GRU 85th GTsSS military unit 26165 and says it has been active since at least 2004 (Confirmed [105]). One of the sources ATT&CK cites for that sentence, SecureWorks' TG-4127 report of 16 June 2016, gives no start year; it assesses with moderate confidence that the group gathers intelligence for the Russian government (Confirmed [106]). No source opened for this study names a dated 2004 APT28 event (Confirmed [105][106]). The [Russia study](/case-studies/THREAT_ACTORS_RUSSIA.md) and [Fancy Bear Goes Phishing](/case-studies/FANCY_BEAR_GOES_PHISHING_CASES.md) carry the group's record.

### APT1's first persona and first domain

Mandiant's APT1 report (February 2013) says the persona UglyGorilla has been active in network operations since October 2004, and on 16 January 2004 asked on the PLA Daily's China Military Online forum whether China has cyber troops (Confirmed [107]). The first APT1 zone Mandiant knew, hugesoft.org, was registered through eNom on 25 October 2004 with a registrant e-mail tied to UglyGorilla, and APT1 registered at least 107 zones from 2004 on (Confirmed [107]). Mandiant directly observed WEBC2 backdoor use from July 2006, but records a first WEBC2-KT3 compile time of 23 January 2004, which it says suggests WEBC2 development since early 2004. Compile times can be altered, so 2004 use is Inferred [107]. ATT&CK's [WEBC2 (S0109)](/mitre/software/S0109.md) uses the observed date: used by APT1 as early as July 2006 (Confirmed [109]).

Mandiant assesses that APT1 is believed to be PLA General Staff Department 3rd Department, 2nd Bureau, Unit 61398, revising its 2010 position that the Chinese government may authorize the activity but that its involvement could not be determined (Confirmed [107]; the attribution is Mandiant's assessment). ATT&CK's [APT1 (G0006)](/mitre/groups/G0006.md) carries the same attribution, gives no start year, and lists T1583.001 for the group's domain registrations (Confirmed [108]). The [China study](/case-studies/THREAT_ACTORS_CHINA.md) and [The Hacker and the State](/case-studies/HACKER_AND_THE_STATE_CASES.md) are the homes; the [APT41 study](/case-studies/APT41_PUBLIC_RECORD.md) shows how much more evidence a confident attribution now carries (Inferred).

### Titan Rain

Everything here is TIME's reporting of 29 August 2005 (Reported [110]). Sandia analyst Shawn Carpenter made his first discoveries about intrusions code-named Titan Rain in March 2004, after a September 2003 Lockheed Martin break-in, and by October 2004 the Army had passed him to the FBI. Targets named include Lockheed Martin, Sandia, Redstone Arsenal, NASA and the World Bank, with reported theft of Army flight-planning software and Mars Reconnaissance Orbiter schematics. The attacks were traced to three routers in Guangdong. Officials said they did not know whether the spying was official, and China's State Council called the charges groundless. Sandia later fired Carpenter and revoked his clearance, and the US Attorney declined to pursue charges against him (Reported [110]). No ATT&CK group, software or campaign object covers Titan Rain, and no other study on main covers it, so this chronicle is its summary home (Reported [110]; Demonstrated [121]).

### The Athens wiretaps

Prevelakis and Spinellis wrote in IEEE Spectrum (29 June 2007) that rogue software in Vodafone Greece's Ericsson AXE switches tapped about 100 phones, the Prime Minister's among them, beginning sometime in the run-up to the August 2004 Athens Olympics (Reported [111]). By their account the implant abused the switches' lawful-intercept subsystem, bypassed the audited management interface so the taps left no normal records, hid its own processes and code blocks, and included a backdoor command sequence (Reported [111]). Undelivered-SMS errors on 24 January 2005 led to Ericsson telling Vodafone of unauthorized software on 4 March 2005, and removal was ordered on 8 March. A Vodafone network-planning manager was found hanged on 9 March 2005; the death was ruled an apparent suicide, the ruling is disputed, and no link to the wiretaps is established (Reported [111]). The article says the perpetrators remain unidentified and discusses, without endorsing, theories involving insiders and US agencies (Reported [111]). The Intercept (James Bamford, 28 September 2015) attributes the operation to the United States with the NSA as the likely operator. It relies on Greek prosecutors' material, anonymous former officials, and Snowden documents that show NSA support for the Olympics and network exploitation against Greek providers, which show capability rather than this tap. No government has admitted it (Reported [112]). No ATT&CK object maps the operation, and this study binds none (Inferred).

### Equation, Regin and Darkhotel: dates without events

- **Equation.** Kaspersky's Equation Q&A (February 2015) dates Equation's network-exploitation operations to 2001, perhaps 1996. It says EQUATIONLASER was used around 2001 to 2004, though another section says 2001 to 2003, and that EQUATIONDRUG was developed from 2003 to 2013 (Confirmed [113]). Its IOC appendix records an EquationLaser installer compiled on 18 October 2004; activity on that date is Inferred because compile timestamps can be altered [113]. Neither Kaspersky's paper nor ATT&CK's [Equation (G0020)](/mitre/groups/G0020.md) names a state sponsor (Confirmed [113][114]). The [United States actors study](/case-studies/THREAT_ACTORS_UNITED_STATES.md) and [NSA and CIA tool leaks](/case-studies/NSA_CIA_TOOL_LEAKS.md) are the homes; that study records the public attribution debate, and neither Kaspersky nor ATT&CK names a sponsor (Confirmed [113][114]).
- **Regin.** Kaspersky (24 November 2014) says some Regin samples carry timestamps back to 2003 and that the operation is likely nation-state supported, names no state, and warns that timestamps could be altered (Confirmed [115]). It is context, not a 2004 event; ATT&CK's [Regin (S0019)](/mitre/software/S0019.md) page exists in the library (Demonstrated [125]).
- **Darkhotel.** ATT&CK's [Darkhotel (G0012)](/mitre/groups/G0012.md) calls it a suspected South Korean group that has targeted victims mainly in East Asia since at least 2004 (Confirmed [116]). Kaspersky's November 2014 report says the actor had operated for almost a decade, that related samples circulated in 2007, and that server logs record connections from 1 January 2009. It notes Korean strings but makes no state attribution, so no dated 2004 event stands behind ATT&CK's 2004 start (Confirmed [117]). The [other states study](/case-studies/THREAT_ACTORS_OTHER_STATES.md) is the home.

## Part 5: crime and prosecutions

### Spam and phishing

- **CAN-SPAM's first year.** The Act (Public Law 108-187, approved 16 December 2003) took effect on 1 January 2004, except section 9 (Confirmed [56]). On 10 March AOL, EarthLink, Microsoft and Yahoo jointly filed six lawsuits against hundreds of defendants, the first major industry suits under the law (Confirmed [59]). On 29 April DOJ announced the first criminal charges, against four Detroit-area defendants accused of sending hundreds of thousands of commercial e-mails with false or fraudulent headers, which had drawn more than 10,000 FTC complaints since 1 January (Confirmed [57]). The FTC announced its first CAN-SPAM cases the same day, against Phoenix Avatar of Detroit and Global Web Promotions of Australia, alleging forged sender addresses and no opt-out (Confirmed [58]; allegations). The [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) is the home for the Act's passage.
- **Hill.** Zachary Keith Hill of Houston, who had pleaded guilty on 9 February, was sentenced to 46 months (announced 18 May) for sending spam posing as America Online and PayPal that sent victims to a look-alike billing page and defrauded them of nearly $50,000 (Confirmed [63]).
- **The phishing count.** DOJ's Web Snare release quotes an Anti-Phishing Working Group count of unique phishing attacks rising from 176 in January 2004 to 1,422 in June 2004. The APWG source was not opened (Reported [69]).
- **Digital PhishNet.** On 8 December industry and law enforcement launched Digital PhishNet, a joint operation against phishing (Confirmed [73]). The [e-commerce threats study](/case-studies/ECOMMERCE_THREATS.md) carries the phishing and card-fraud thread forward.

### Piracy

- **Operation Fastlink.** Searches began on 21 April and DOJ announced the operation on 22 April: more than 120 searches in 27 states and 10 foreign countries against online piracy groups, nearly 100 individuals identified, coordinated by the FBI Cyber Division and CCIPS, and called the largest multinational enforcement effort against online piracy to that date (Confirmed [62]). DOJ's December index lists the first guilty plea by a Fastlink defendant on 22 December; only the index title was read (Confirmed [75][76]).
- **Operation Digital Gridlock.** On 25 August DOJ executed six search warrants in Texas, New York and Wisconsin against The Underground Network's Direct Connect hubs, the first federal criminal enforcement action against copyright piracy on peer-to-peer networks (Confirmed [68]).

### Operation Web Snare

The operation ran from 1 June to 26 August and produced more than 160 investigations, 117 complaints, informations and indictments, and more than 150 arrests or convictions, with more than 150,000 victims and estimated losses over $215 million (Confirmed [69]). Roman Vega appeared in court after extradition from Cyprus, and the Attorney General directed full use of the new aggravated identity theft law (Confirmed [69]). Within it, Orbit Communication's CEO Jay Echouafni was indicted for hiring attackers in Arizona, Louisiana, Ohio and the UK to run DDoS attacks on competitors from October 2003, causing more than $2 million in losses, which DOJ called the first case of DDoS for commercial advantage (Confirmed [69]; allegations). The release also quotes IC3 referring 71,442 Internet fraud complaints to law enforcement in 2003 and 42,183 in the first half of 2004, and the FTC saying Internet-related complaints were 55 percent of consumer fraud reports in 2003 (Reported [69]). [Four Books on Cybercrime](/case-studies/CYBERCRIME_FOUR_BOOKS.md) is the home for the Echouafni case (Demonstrated [127]).

### Shadowcrew and Operation Firewall (summary)

On 28 October DOJ announced a 62-count Newark indictment of 19 people who ran Shadowcrew, a site of about 4,000 members that trafficked at least 1.7 million stolen card numbers, with losses over $4 million; 21 people were arrested in the US that week, with more abroad (Confirmed [71]; allegations). The Secret Service said Operation Firewall, begun in July 2003 as an access-device fraud case and using court-authorized intercepts from early 2004, made 28 arrests in eight states and six countries against Shadowcrew, Carderplanet and Darkprofits, with losses over $4.3 million (Confirmed [72]). [Four Books on Cybercrime](/case-studies/CYBERCRIME_FOUR_BOOKS.md) is the home (Demonstrated [127]).

### The bookmaker extortion (summary)

The Register reported that the UK's National Hi-Tech Crime Unit and Russian police arrested three suspected leaders of a DDoS extortion racket against online bookmakers on 20 July, in raids in St Petersburg, Saratov and Stavropol; bookmakers had faced attacks and demands since October 2003, and ten gang members had been arrested in Riga in November 2003 (Reported [64]). [Four Books on Cybercrime](/case-studies/CYBERCRIME_FOUR_BOOKS.md) is the home.

### Data theft and intrusion

- **Acxiom.** On 21 July Scott Levine of Snipermail was indicted in Little Rock on 144 counts, 139 of them illegal-access counts covering about 8.2 GB downloaded from an Acxiom FTP server between April 2002 and August 2003. DOJ put the loss over $7 million and said there was no evidence the data was misused (Confirmed [65][66]; allegations). An earlier Acxiom intrusion by Daniel Baas, found in July 2003, led investigators to this second set (Confirmed [65]).
- **Ingram Micro.** On 4 August six people were indicted in the Central District of California in a scheme to steal more than $10 million in equipment. Calin Mateias of Bucharest allegedly hacked Ingram Micro's online ordering system from 1999 onward and recruited US mail drops (Confirmed [67]; allegations).
- **MicroPatent.** From 3 February Myron Tereshchuk sent extortion e-mails demanding $17 million from MicroPatent's president, threatening to disclose proprietary data and to launch DDoS attacks. He had gained unauthorized access to MicroPatent's network and sent mail through unsecured residential and business wireless networks. He pleaded guilty on 8 June in the Eastern District of Virginia (Confirmed [61]).
- **Lowe's.** On 15 December Brian Salcedo was sentenced in the Western District of North Carolina to 108 months for a conspiracy that ran from October to 9 November 2003. It entered Lowe's network through a store wireless network in Southfield, Michigan, reached the central system in North Wilkesboro, and installed a program meant to capture customer card data. DOJ said the previous longest federal hacking sentence was Mitnick's 68 months (Confirmed [74]). The [Mitnick intrusions study](/case-studies/MITNICK_INTRUSIONS.md) is the home for that case.
- **BJ's Wholesale Club (boundary).** On 16 June 2005 the FTC alleged that BJ's did not encrypt card data in transit or in store, kept it for up to 30 days, did not block unauthorized wireless access and used default user IDs and passwords. It said fraudulent purchases ran to millions of dollars, with about $13 million in outstanding claims by May 2005 (Confirmed [77]; allegations). The FTC pages do not date the intrusion, so placing it in 2004 is Inferred and not checked.

### Insiders and leaks

- **The FBI's case system.** An FBI headquarters legal technician was sentenced to 12 months in prison for unlawfully accessing the FBI's Automated Case Support system, after a guilty plea in December 2003 (Confirmed [60]).
- **Windows source code.** On 12 February Microsoft learned that portions of the Windows 2000 and Windows NT 4.0 source code had been illegally posted online. Microsoft said this did not result from a breach of its corporate network and that it was working with the FBI (Confirmed [48]).

### Spyware

On 12 October the FTC sued Seismic Entertainment Productions, Smartbot.Net and Sanford Wallace in New Hampshire, alleging that they installed spyware without consent by exploiting an Internet Explorer feature and then sold the products Spy Wiper and Spy Deleter (Confirmed [70]; allegations).

## Part 6: law, policy and standards

### United States law and policy

- **CAN-SPAM (1 January).** Part 5.
- **GAO-04-354 (15 March, released 30 March).** Critical Infrastructure Protection: Challenges and Efforts to Secure Control Systems recommended that DHS build a strategy to coordinate control-system security with the private sector and other agencies; GAO lists the recommendation as closed and implemented. Only the product page was read (Confirmed [80]).
- **The blackout final report (April).** The US-Canada Power System Outage Task Force's Security Working Group found no evidence that a malicious cyber attack directly or indirectly caused the 14 August 2003 outage. It reviewed a DHS NCS correlation study of Blaster and cited Slammer's January 2003 effect on monitoring computers at Davis-Besse (Confirmed [81]). Its Group III, Physical and Cyber Security of North American Bulk Power Systems, made recommendations 32 to 44: among them, implement NERC IT standards, improve IT forensic capability, detect wireless and remote wireline intrusion, and confirm NERC ES-ISAC as the central point for sharing security information (Confirmed [81]). The industrial thread runs on through [Stuxnet](/case-studies/STUXNET.md), the [ICS attacks and advisories study](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md) and the [ICS ATT&CK Atlas](/ICS_ATTACK_ATLAS.md) (Inferred).
- **Identity Theft Penalty Enhancement Act (15 July).** Public Law 108-275 added 18 U.S.C. 1028A, aggravated identity theft, with a mandatory added two-year prison term (Confirmed [87]). At the signing the White House said nearly 10 million Americans had their identities stolen the previous year, with nearly $50 billion in fraudulent transactions; that is the White House's figure and was not checked independently (Confirmed [88]).
- **HSPD-12 (27 August).** Policies for a Common Identification Standard for Federal Employees and Contractors required the Secretary of Commerce to issue the standard within six months (Confirmed [89]).
- **Intelligence Reform and Terrorism Prevention Act (17 December).** Public Law 108-458; section 1016 (6 USC 485) sets up information sharing. A search of the law's text found no use of the word "cyber" (Confirmed [90]).

### International

The Convention on Cybercrime (ETS 185) was done at Budapest on 23 November 2001 (Confirmed [91]). Its entry into force was not checked, because the Treaty Office page refused the request. The [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) is the home for the Convention.

### NIST

- **SP 800-61 (January).** Computer Security Incident Handling Guide; it superseded SP 800-3 of 1991 and was withdrawn on 7 March 2008 in favor of Revision 1 (Confirmed [78]).
- **FIPS 199 (February).** Standards for Security Categorization of Federal Information and Information Systems (Confirmed [79]).
- **SP 800-37 (May).** Guide for the Security Certification and Accreditation of Federal Information Systems (Confirmed [82]).
- **SP 800-67 (May).** Recommendation for the Triple Data Encryption Algorithm (TDEA) Block Cipher (Confirmed [83]).
- **SP 800-64 Rev. 1 (June).** Security Considerations in the Information System Development Life Cycle, superseding the October 2003 original (Confirmed [84]).
- **SP 800-72 (November).** Guidelines on PDA Forensics (Confirmed [85]).
- **Just after the year.** The original SP 800-53 control catalog came in February 2005, so the 2004 set had categorization, certification and accreditation, and incident handling, but no control baseline yet (Confirmed [86]).

### Networks, wireless and identity

- **RFC 3704 (March).** BCP 84, Ingress Filtering for Multihomed Networks, updates RFC 2827 (BCP 38), which aims to limit DDoS by denying traffic with spoofed source addresses (Confirmed [94]).
- **RFC 3748 (June).** Extensible Authentication Protocol, Standards Track, obsoleting RFC 2284 (Confirmed [93]).
- **IEEE 802.11i-2004 (24 July).** Amendment 6, MAC Security Enhancements, defines TKIP and CCMP as more robust than WEP and introduces security associations into 802.11; it is now superseded (Confirmed [92]). The [wireless security reference](/WIRELESS_SECURITY_REFERENCE.md) covers the protocols that followed.
- **RFC 3833 (August).** Threat Analysis of the Domain Name System notes that DNSSEC had been in development for most of a decade without the IETF writing down the threats it addresses (Confirmed [95]).
- **ISO/IEC 13335-1:2004 (November).** Concepts and models for ICT security management, Edition 1, now withdrawn (Confirmed [96]).

### Cryptography

Wang, Feng, Lai and Yu posted "Collisions for Hash Functions MD4, MD5, HAVAL-128 and RIPEMD" to the IACR ePrint archive (2004/199), received on 16 August and last revised on 17 August (Confirmed [97]). No 2004 attack in the record opened here used the result (Inferred). The [cryptography reference](/CRYPTOGRAPHY_REFERENCE.md) covers the move away from MD5.

## Part 7: the defender view

**Defaults changed.** Microsoft released Windows XP SP2 to manufacturing on 6 August with stronger default security settings; its lifecycle start date is 17 September, and it was supported until 14 July 2010 (Confirmed [49][51]). US-CERT's SA04-243A said SP2 enables Windows Firewall in almost all configurations and adds an IE Local Machine Zone lockdown that protects against attacks such as Download.Ject (Confirmed [50]). SP2 introduced Data Execution Prevention, hardware-enforced on capable processors and software-enforced. Software DEP was on by default for core operating system components and services, and the default policy was OptIn, with OptOut, AlwaysOn and AlwaysOff available (Confirmed [52]). Microsoft says DEP stops code running from data pages such as the default heap, stacks and memory pools (Confirmed [53]). OptIn meant most applications were not covered at first (Inferred [52]). SP2 was also not vulnerable by default to the GDI+ JPEG flaw or the IFRAME flaw (Confirmed [19][23]).

**Process changed.** Microsoft says the SDL became an integral part of its software development process in 2004 (Confirmed [54]). The [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) is the home for the SDL's start.

**The window between fix and worm was short, and sometimes reversed (Inferred for the trend).** Witty began the day after its flaw was publicized (Confirmed [37]). Sasser came within weeks of MS04-011 (Confirmed [9][41]; Inferred for the interval). MS04-025 and MS04-040 fixed flaws already being exploited, and MS04-025 shipped off the monthly day (Confirmed [18][25]; Inferred for the cycle). The [Log4Shell study](/case-studies/LOG4SHELL.md) shows the same pattern at larger scale, and the [zero-day market study](/case-studies/ZERO_DAY_MARKET_EVENTS.md) follows the market for unpatched flaws (Inferred).

**Security products became targets.** Witty's whole vulnerable population ran ISS security software, CA-2004-01 warned about H.323 inspection in firewalls, and NVD's CVE-2003-0819 is an overflow inside ISA Server's firewall filter (Confirmed [37][1][4]).

**The mail gateway took the load.** CA-2004-02's controls were antivirus with automatic updates, attachment filtering and quarantine at the gateway, a personal firewall, and users who do not run programs of unknown origin (Confirmed [1]). The same set is still in use (Inferred). The [email security reference](/EMAIL_SECURITY_REFERENCE.md) covers what came after.

**The browser and the web server became one attack.** Download.Ject chained an unpatched IIS server to an unpatched browser (Confirmed [44]). The year's patch advice for web operators and users was separate; the attack joined them (Inferred).

**Wireless was an unguarded door.** The Lowe's case went through a store's wireless network, Tereshchuk mailed through unsecured networks, and the FTC alleged BJ's failed to block unauthorized wireless access; 802.11i arrived in July (Confirmed [74][61][77][92]).

**Rewards and informants worked once.** The Sasser arrest is the year's clearest case of a reward program leading to an arrest (Confirmed [41]). The original MyDoom.B reward produced no arrest in the sources opened here (Inferred [33]).

**Infrastructure advisories reached the routing layer.** TA04-111A's session-reset warning singled out BGP, and RFC 3704 extended ingress filtering (Confirmed [14][94]).

## Part 8: MITRE mappings

No 2004 record carries an ATT&CK, CWE, CAPEC or CVSS id from the time (Confirmed [98][99][100]; Inferred for ATT&CK). Every Enterprise binding below is this study's later mapping (Inferred). The exceptions are the objects ATT&CK itself dates to 2004 (Confirmed [104][105][116]). Every id was checked against the library's data files and the generated pages under `mitre/` (Demonstrated [120][121][122][123][124][125]). Names and tactics are those of ATT&CK v20.0 as the library carries them.

The Basis column says how strong each tie is, as in the [2016 chronicle](/case-studies/CHRONICLE_2016.md). **Listed** means ATT&CK itself lists the id for the event or object. **Described** means a primary source describes the behavior and this study assigns the id. **Reported** means only a secondary source supports the behavior. **Inferred** means no source describes the behavior in enough detail and the mapping rests on the study's reading.

### ATT&CK Enterprise techniques

| Id | Name (ATT&CK v20.0) | Tactic(s) | Basis | Dated event or report | Sources |
|---|---|---|---|---|---|
| [`T1566.001`](/mitre/techniques/T1566-001.md) | Spearphishing Attachment | initial-access | Inferred | Mass-mailed, not targeted, so the closest fit only: Bagle and Novarg attachments (CA-2004-02, 27 Jan); MyDoom.B (SA04-028A, 28 Jan) | [1][32] |
| [`T1204.002`](/mitre/techniques/T1204-002.md) | Malicious File | execution | Described | CA-2004-02: the mailers spread through social engineering and human action (27 Jan) | [1] |
| [`T1566.002`](/mitre/techniques/T1566-002.md) | Spearphishing Link | initial-access | Described | Bofra spread through links in e-mail (TA04-315A, 10 Nov) | [24] |
| [`T1598.003`](/mitre/techniques/T1598-003.md) | Spearphishing Link | reconnaissance | Described | Hill's spam posing as AOL and PayPal sent victims to a look-alike billing page (sentenced 17 May); CA-2004-02's definition of phishing | [63][1] |
| [`T1684.002`](/mitre/techniques/T1684-002.md) | Email Spoofing | stealth | Described | MyDoom.B spoofs From addresses (28 Jan); the first CAN-SPAM charges and FTC cases over false headers and forged sender addresses (29 Apr, alleged). T1672 is revoked and superseded by T1684.002 | [32][57][58][122] |
| [`T1087.003`](/mitre/techniques/T1087-003.md) | Email Account | discovery | Described | Address harvesting from address books and files (CA-2004-02); MyDoom.M/O searches on harvested addresses (26 Jul) | [1][46] |
| [`T1105`](/mitre/techniques/T1105.md) | Ingress Tool Transfer | command-and-control | Described | Bagle's backdoor downloads and runs programs (18 Jan); backdoors used to download DDoS tools (CA-2004-02) | [34][1] |
| [`T1090`](/mitre/techniques/T1090.md) | Proxy | command-and-control | Described | MyDoom's backdoor can act as a proxy (F-Secure) | [35] |
| [`T1584.005`](/mitre/techniques/T1584-005.md) | Botnet | resource-development | Described | Phatbot controls large numbers of systems (SA04-079A, 19 Mar); compromised home machines used for DDoS and spam (CA-2004-02) | [36][1] |
| [`T1498`](/mitre/techniques/T1498.md) | Network Denial of Service | impact | Described | MyDoom's scheduled SCO flood (from 1 Feb); MyDoom.B designed to attack microsoft.com; Echouafni's hired DDoS (Web Snare, 26 Aug, alleged); the bookmaker attacks (Reported) | [35][33][69][64][119] |
| [`T1685`](/mitre/techniques/T1685.md) | Disable or Modify Tools | defense-impairment | Inferred | MyDoom.B blocks anti-virus vendor sites and may stop anti-virus updates (28 and 29 Jan); blocking updates is a loose fit. T1562.001 is revoked and superseded by T1685 | [33][32][122] |
| [`T1210`](/mitre/techniques/T1210.md) | Exploitation of Remote Services | lateral-movement | Described | Sasser through LSASS (about 1 May); Phatbot through unpatched Windows flaws (19 Mar); Witty host to host (19 Mar) | [43][36][37][38] |
| [`T1046`](/mitre/techniques/T1046.md) | Network Service Discovery | discovery | Described | Sasser scans random addresses on TCP 445 | [43] |
| [`T1190`](/mitre/techniques/T1190.md) | Exploit Public-Facing Application | initial-access | Described | Witty's single UDP packet to ISS PAM (19 Mar); Download.Ject on IIS 5.0 servers without MS04-011 (24 Jun); Santy.A on phpBB (21 Dec) | [37][38][44][28] |
| [`T1189`](/mitre/techniques/T1189.md) | Drive-by Compromise | initial-access | Described | Download.Ject's compromised servers deliver code to visitors (Jun); Bofra (Nov); spyware installed through an IE feature (FTC, 12 Oct, alleged) | [44][45][23][70] |
| [`T1203`](/mitre/techniques/T1203.md) | Exploitation for Client Execution | execution | Described | CAN-2004-0549 exploited (TA04-163A, 11 Jun; MS04-025); CAN-2004-1050 exploited (MS04-040, 1 Dec) | [17][18][25] |
| [`T1593.002`](/mitre/techniques/T1593-002.md) | Search Engines | reconnaissance | Described | Santy.A finds targets through search-engine keyword queries (21 Dec) | [28] |
| [`T1491.002`](/mitre/techniques/T1491-002.md) | External Defacement | impact | Described | Santy.A defaces web files (21 Dec) | [28] |
| [`T1561.001`](/mitre/techniques/T1561-001.md) | Disk Content Wipe | impact | Described | Witty writes data to random disk locations and overwrites sections of the hard drive (19 Mar) | [37][38] |
| [`T1669`](/mitre/techniques/T1669.md) | Wi-Fi Networks | initial-access | Described | The Lowe's store wireless network (2003 conduct; sentence 15 Dec 2004); Tereshchuk's mail through unsecured wireless networks (plea 8 Jun) is a weaker fit | [74][61][118] |
| [`T1657`](/mitre/techniques/T1657.md) | Financial Theft | impact | Described | Hill's phishing fraud (17 May); Tereshchuk's $17 million demand (from 3 Feb); Ingram Micro orders (4 Aug, alleged); Shadowcrew card trafficking (28 Oct, alleged) | [63][61][67][71] |
| [`T1583.001`](/mitre/techniques/T1583-001.md) | Domains | resource-development | Listed (group) | ATT&CK lists it for APT1 (G0006); Mandiant dates the first APT1 zone, hugesoft.org, to 25 Oct 2004 | [108][107] |

Left out on purpose: [T1080](/mitre/techniques/T1080.md) Taint Shared Content for MyDoom's copy into the Kazaa shared folder, because a file-sharing folder is not the shared storage the technique describes (Inferred). [T1195.002](/mitre/techniques/T1195-002.md) Compromise Software Supply Chain for the CVS overflow, because TA04-147A describes a risk, not an observed alteration (Confirmed [15]; Inferred). [T1686](/mitre/techniques/T1686.md) Disable or Modify System Firewall (T1562.004 before ATT&CK v19 revoked it; Demonstrated [122]), because CA-2004-02 says only that a virus may disable a firewall (Confirmed [1]; Inferred). [T1078](/mitre/techniques/T1078.md) Valid Accounts for the FBI technician and Levine, because the releases do not say how access was gained (Confirmed [60][65]). The TCP reset weakness, which no source records as exploited (Confirmed [14]). Cabir, which belongs to ATT&CK Mobile and has no verified mapping here (Confirmed [47]; Inferred). The Athens wiretaps and Titan Rain, which no ATT&CK object covers and whose only sources are Reported (Reported [110][111]).

### Techniques ATT&CK lists for objects it dates to 2004

ATT&CK draws these from later analyses, not from a dated 2004 event, so they are not in this study's Navigator layer apart from T1583.001 above (Confirmed [103][109][114]; Inferred).

| Id | Name (ATT&CK v20.0) | Tactic(s) | Object | Basis | Sources |
|---|---|---|---|---|---|
| [`T1014`](/mitre/techniques/T1014.md) | Rootkit | stealth | S0022 Uroburos (kernel module hides host components); binding to the 2004 build is Inferred | Listed (object) | [103] |
| [`T1059.003`](/mitre/techniques/T1059-003.md) | Windows Command Shell | execution | S0109 WEBC2; 2004 use rests on a compile time | Listed (object) | [109][107] |
| [`T1574.001`](/mitre/techniques/T1574-001.md) | DLL | stealth, execution | S0109 WEBC2; T1574.002 DLL Side-Loading is revoked to T1574.001 | Listed (object) | [109][122] |
| [`T1105`](/mitre/techniques/T1105.md) | Ingress Tool Transfer | command-and-control | S0109 WEBC2 | Listed (object) | [109] |
| [`T1480.001`](/mitre/techniques/T1480-001.md) | Environmental Keying | stealth | G0020 Equation | Listed (group) | [114] |
| [`T1564.005`](/mitre/techniques/T1564-005.md) | Hidden File System | stealth | G0020 Equation | Listed (group) | [114] |
| [`T1120`](/mitre/techniques/T1120.md) | Peripheral Device Discovery | discovery | G0020 Equation | Listed (group) | [114] |
| [`T1542.002`](/mitre/techniques/T1542-002.md) | Component Firmware | stealth, persistence | G0020 Equation | Listed (group) | [114] |

AA23-129A's technique table for Snake lists, among others, [T1014](/mitre/techniques/T1014.md) Rootkit, [T1027](/mitre/techniques/T1027.md) Obfuscated Files or Information, [T1036](/mitre/techniques/T1036.md) Masquerading, [T1040](/mitre/techniques/T1040.md) Network Sniffing, [T1056.001](/mitre/techniques/T1056-001.md) Keylogging, [T1071.001](/mitre/techniques/T1071-001.md) Web Protocols, [T1090.003](/mitre/techniques/T1090-003.md) Multi-hop Proxy, [T1095](/mitre/techniques/T1095.md) Non-Application Layer Protocol, [T1106](/mitre/techniques/T1106.md) Native API, [T1112](/mitre/techniques/T1112.md) Modify Registry, [T1132.002](/mitre/techniques/T1132-002.md) Non-Standard Encoding, [T1140](/mitre/techniques/T1140.md) Deobfuscate/Decode Files or Information, [T1572](/mitre/techniques/T1572.md) Protocol Tunneling, [T1573](/mitre/techniques/T1573.md) Encrypted Channel and [T1587.001](/mitre/techniques/T1587-001.md) Malware (Confirmed [102]; names Demonstrated [120]). The advisory also lists T1574.002, which ATT&CK v20.0 revokes to T1574.001 (Demonstrated [122]). These describe the implant as analysed in 2023, so none is presented as observed in 2004 (Inferred).

### ATT&CK for ICS

No 2004 event in the record opened here touches an industrial control system. GAO-04-354 and the blackout final report are policy records about control systems, not intrusions (Confirmed [80][81]). This study therefore has no ATT&CK for ICS table and no ICS layer (Inferred).

### ATT&CK groups, software and campaigns

| Object | Id | Binding | Sources |
|---|---|---|---|
| Turla | [G0010](/mitre/groups/G0010.md) | Bound for the start of Snake operations: AA23-129A puts first operations shortly after early 2004, and ATT&CK dates victims since at least 2004 | [102][104] |
| Uroburos (Snake) | [S0022](/mitre/software/S0022.md) | Bound: initial versions complete around early 2004 | [102][103] |
| APT28 | [G0007](/mitre/groups/G0007.md) | Bound with a caveat: ATT&CK says active since at least 2004; no source opened names a dated 2004 event | [105][106] |
| APT1 | [G0006](/mitre/groups/G0006.md) | Bound: Mandiant dates the UglyGorilla persona (16 Jan, Oct) and the first domain (25 Oct) to 2004 | [107][108] |
| WEBC2 | [S0109](/mitre/software/S0109.md) | Bound with a caveat: a 23 Jan 2004 compile time; ATT&CK dates observed use to July 2006 | [107][109] |
| Equation | [G0020](/mitre/groups/G0020.md) | Bound with a caveat: EquationLaser used around 2001 to 2004 and an installer compiled 18 Oct 2004; no state named | [113][114] |
| Darkhotel | [G0012](/mitre/groups/G0012.md) | Bound with a caveat: ATT&CK says since at least 2004; Kaspersky's earliest evidence is 2007 samples | [116][117] |
| Regin | [S0019](/mitre/software/S0019.md) | Context only: timestamps back to 2003; not a 2004 event | [115] |

No campaign object is bound. No ATT&CK object covers any 2004 worm, Titan Rain or the Athens wiretaps (Demonstrated [121]).

### CWE and CAPEC

NVD's CWE ids for these CVEs can only have been assigned after the CWE List's first release in 2006 (Confirmed [98]; Inferred for the assignment dates). The row marked NVD carries the CWE NVD lists; the others are this study's classes (Inferred). Names are those in the library's CWE and CAPEC data, and every CAPEC listed has a page under `/mitre/capec/` (Demonstrated [124][125]). The library has no per-CWE generated pages, so CWE ids are plain text; the [CWE reference](/CWE_REFERENCE.md) is the library's entry point (Demonstrated [125]).

| CWE | Weakness (library name) | Basis | 2004 record | CAPEC |
|---|---|---|---|---|
| CWE-119 | Improper Restriction of Operations within the Bounds of a Memory Buffer | NVD | ISA Server H.323 filter (CVE-2003-0819, CA-2004-01) | [CAPEC-100](/mitre/capec/CAPEC-100.md) Overflow Buffers; [CAPEC-24](/mitre/capec/CAPEC-24.md) Filter Failure through Buffer Overflow (this study's pairing: the overflow is inside a filter) |
| NVD-CWE-Other | (as NVD lists it) | NVD | LSASS (CVE-2003-0533), PCT (CVE-2003-0719), ASN.1 (CVE-2003-0818), ISS PAM (CVE-2004-0362), IE (CVE-2004-0549), GDI+ (CVE-2004-0200), libpng (CVE-2004-0597), phpBB (CVE-2004-1315) | See the study classes below |
| CWE-121 | Stack-based Buffer Overflow | Study's class | LSASS and ISS PAM, which the CVE records and NVD describe as stack-based | [CAPEC-100](/mitre/capec/CAPEC-100.md) Overflow Buffers; [CAPEC-24](/mitre/capec/CAPEC-24.md) for Witty's target, a security filter |
| CWE-190 | Integer Overflow or Wraparound | Study's class | ASN.1 (CVE-2003-0818, "multiple integer overflows") | [CAPEC-92](/mitre/capec/CAPEC-92.md) Forced Integer Overflow |
| CWE-94 | Improper Control of Generation of Code | Study's class | phpBB highlight parameter (CVE-2004-1315), remote PHP code execution | [CAPEC-242](/mitre/capec/CAPEC-242.md) Code Injection |
| CWE-328 | Use of Weak Hash | Study's class | MD5 after the August collisions | [CAPEC-97](/mitre/capec/CAPEC-97.md) Cryptanalysis |
| CWE-311 and CWE-1392 | Missing Encryption of Sensitive Data; Use of Default Credentials | Study's class | The FTC's BJ's allegations (2005); both ids checked on cwe.mitre.org [101] | None assigned |
| none bound | (phishing) | Library data | Mass mailers and phishing pages | [CAPEC-163](/mitre/capec/CAPEC-163.md) Spear Phishing (the library lists it on T1566.001, T1566.002 and T1598.003); [CAPEC-98](/mitre/capec/CAPEC-98.md) Phishing (on the parents T1566 and T1598) |
| none bound | (scanning) | Library data | Sasser's scans of TCP 445 | [CAPEC-300](/mitre/capec/CAPEC-300.md) Port Scanning (the library lists it on T1046) |
| none bound | (security tools blocked) | Library data | MyDoom.B blocking anti-virus updates | [CAPEC-578](/mitre/capec/CAPEC-578.md) Disable Security Software (the library lists it on T1685) |
| none bound | (downloads) | Study's pairing | Backdoors that download further tools | [CAPEC-185](/mitre/capec/CAPEC-185.md) Malicious Software Download |
| none bound | (flooding) | Study's pairing | MyDoom's floods; Echouafni's DDoS | [CAPEC-125](/mitre/capec/CAPEC-125.md) Flooding |

### D3FEND countermeasures

The technique-to-countermeasure links come from the library's D3FEND data unless the row says the pairing is this study's; pairing them with the 2004 advice is this study's reading (Demonstrated [123]; Inferred). Every page exists under `/mitre/d3fend/` (Demonstrated [125]).

| Technique from the record | D3FEND countermeasures | 2004 analogue |
|---|---|---|
| T1190, T1203, T1210, T1189 | [Process Segment Execution Prevention](/mitre/d3fend/process-segment-execution-prevention.md) (D3-PSEP) | XP SP2's DEP, the year's direct dated instance of the countermeasure (6 Aug) [52][53] |
| T1203, T1210 (D3-SFCV); T1190, T1189, T1203, T1210 (D3-SAOR) | [Stack Frame Canary Validation](/mitre/d3fend/stack-frame-canary-validation.md) (D3-SFCV); [Segment Address Offset Randomization](/mitre/d3fend/segment-address-offset-randomization.md) (D3-SAOR) | Later memory protections against the year's stack overflows; neither was 2004 Windows advice (Inferred) [11][38] |
| T1105, T1190, T1210, T1566.001, T1566.002 (D3-NTF); T1190, T1566.001, T1566.002 (D3-ITF) | [Network Traffic Filtering](/mitre/d3fend/network-traffic-filtering.md) (D3-NTF); [Inbound Traffic Filtering](/mitre/d3fend/inbound-traffic-filtering.md) (D3-ITF) | MS04-011's port blocks and Internet Connection Firewall; CA-2004-01's filtering of 1720/TCP and 1720/UDP [9][1] |
| T1190, T1210, T1105 | [Network Traffic Signature Analysis](/mitre/d3fend/network-traffic-signature-analysis.md) (D3-NTSA) | The IDS layer, which was itself Witty's target [37] |
| T1105 | [Outbound Traffic Filtering](/mitre/d3fend/outbound-traffic-filtering.md) (D3-OTF) | CA-2004-02's personal firewall against backdoor downloads [1] |
| T1210 | [Connection Attempt Analysis](/mitre/d3fend/connection-attempt-analysis.md) (D3-CAA); [RPC Traffic Analysis](/mitre/d3fend/rpc-traffic-analysis.md) (D3-RTA, this study's pairing; no library link) | Sasser's scans of TCP 445; the LSASS DCE/RPC interface [43][11] |
| T1566.001, T1566.002 | [Email Filtering](/mitre/d3fend/email-filtering.md) (D3-EF); [Sender Reputation Analysis](/mitre/d3fend/sender-reputation-analysis.md) (D3-SRA) | CA-2004-02's gateway attachment filtering and quarantine [1] |
| T1204.002, T1566.001 (D3-FA); T1204.002 (D3-EAL, D3-EDL) | [File Analysis](/mitre/d3fend/file-analysis.md) (D3-FA); [Executable Allowlisting](/mitre/d3fend/executable-allowlisting.md) (D3-EAL); [Executable Denylisting](/mitre/d3fend/executable-denylisting.md) (D3-EDL) | Antivirus with automatic updates; "do not run programs of unknown origin" [1] |
| T1566.002, T1189 | [URL Analysis](/mitre/d3fend/url-analysis.md) (D3-UA); [URL Reputation Analysis](/mitre/d3fend/url-reputation-analysis.md) (D3-URA) | CA-2004-02's warning about misleading URLs; Bofra's e-mailed links [1][24] |
| T1190, T1203, T1210 (this study's pairing; no library link) | [Software Update](/mitre/d3fend/software-update.md) (D3-SU); [System Vulnerability Assessment](/mitre/d3fend/system-vulnerability-assessment.md) (D3-SYSVA) | MBSA, Windows Update and SUS (MS04-007); the MS04-028 scanning and detection tools [5][19] |
| T1669 (this study's pairing; no library link) | [Message Authentication](/mitre/d3fend/message-authentication.md) (D3-MAN) | 802.11i's CCMP and TKIP [92] |

Techniques not named in this table are left without a D3FEND pairing here. The library links T1561.001 and T1491.002 only to countermeasures with no 2004 analogue, and T1498, T1046, T1669 and T1685 to none (Demonstrated [123]). ATT&CK mitigation pages exist for [M1050 Exploit Protection](/mitre/mitigations/M1050.md) (DEP), [M1051 Update Software](/mitre/mitigations/M1051.md), [M1037 Filter Network Traffic](/mitre/mitigations/M1037.md), [M1049 Antivirus/Antimalware](/mitre/mitigations/M1049.md) and [M1017 User Training](/mitre/mitigations/M1017.md) (Demonstrated [125]).

### Navigator layer

The study's Enterprise techniques are saved as one ATT&CK Navigator layer pinned to ATT&CK v20, [navigator/library-layers/chronicle-2004.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/chronicle-2004.json), in the format of the existing chronicle layers: domain enterprise-attack, navigator 4.9, layer 4.5, described as a curated case-study layer and not an official MITRE mapping (Demonstrated [126]). It lists the 22 techniques in the Enterprise table under each tactic they carry in v20.0 and is listed on [the Navigator layers page](/navigator/index.md). The object-level techniques in the second table are not in it, apart from T1583.001. Scores show the basis, not severity, in the house scale set by the 2016 chronicle: 100 where the source or ATT&CK prints the id, 70 where a primary source describes the behavior and this study assigns the id, 50 where only a Reported source supports it, and 40 for an Inferred mapping (Demonstrated [126]). T1583.001 scores 100 because ATT&CK lists it for APT1; T1566.001 and T1685 score 40; every other row scores 70 (Inferred). Each entry's comment names the source numbers in the Sources table below. No ICS layer is needed (Inferred).

## Cross-cutting themes

**Mail was the year's main delivery path.** CERT/CC's last two advisories split between a protocol-parsing flaw and the mass mailers, and three of the six home-user alerts cited here were about MyDoom, Bagle, Netsky and Phatbot (Confirmed [1][32][36][46]; the count is Inferred). The controls CERT named are the ones still in use (Inferred).

**Attacks moved to the browser.** Download.Ject, Bofra and the FTC's spyware case all installed code through Internet Explorer, and two of those flaws were exploited before or at their fix (Confirmed [44][23][70][18][25]). XP SP2's Local Machine Zone lockdown was the platform's answer (Confirmed [50]).

**The defender's tools were attack surface.** Witty, the H.323 inspection warning and the ISA Server filter overflow all hit the security layer itself (Confirmed [37][1][4]). The [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) records the earlier years (Inferred).

**Defaults started to do the work.** SP2's firewall and DEP and the SDL moved security from advisory text into the product (Confirmed [50][52][54]). Defaults did not reach every application at once: DEP's OptIn default covered system components only (Confirmed [52]; Inferred for the effect).

**Crime organized, and so did the response.** Shadowcrew's market, the bookmaker extortion and hired DDoS met multi-agency sweeps (Fastlink, Web Snare, Firewall), industry suits under CAN-SPAM, a reward program and Digital PhishNet (Confirmed [71][72][62][69][59][41][73]; Reported [64]). The [ransomware ecosystem study](/case-studies/RANSOMWARE_ECOSYSTEM.md) follows where organized extortion went next (Inferred).

**Governance arrived on paper.** SP 800-61, FIPS 199, SP 800-37, HSPD-12, 802.11i and ISO/IEC 13335-1 all date from 2004; the federal control catalog followed in February 2005 (Confirmed [78][79][82][89][92][96][86]).

**State activity was invisible at the time.** Snake's operating start came out in 2023, APT1's first persona and domain in 2013, and EquationLaser's compile time in 2015. Titan Rain was reported by TIME in 2005, and the Athens wiretaps by IEEE Spectrum in 2007 and The Intercept in 2015; only the 2015 account names a perpetrator, partly on anonymous sourcing (Confirmed [102][107][113]; Reported [110][111][112]).

### What is overstated and what is understated

This section is the study's reading of the record (Inferred).

- **Overstated: 2004 as only a worm year.** Mass mailers and worms have CERT, US-CERT and vendor records with dates, so they dominate the dated record [1][32][36].
- **Overstated: Witty's speed.** Its distinction is speed against a small population; CAIDA says Witty took 30 minutes longer than SQL Slammer to infect its vulnerable population [37].
- **Overstated: Download.Ject as a worm.** Microsoft called it a targeted manual attack, not a worm [44].
- **Overstated: Sasser's exact launch day.** The Microsoft record dates only the arrest and says the launch came within the prior seven days [41].
- **Overstated: CERT/CC going quiet.** Two numbered advisories against 28 in 2003 reflect a change of publication channel to US-CERT, not a quieter year [1][2].
- **Overstated: "since 2004" as a dated event.** ATT&CK's 2004 start dates for APT28 and Darkhotel have no dated 2004 event behind them in the sources opened, and Darkhotel's own vendor report says "almost a decade" with 2007 samples [105][106][116][117].
- **Overstated: Titan Rain as a confirmed Chinese government operation.** TIME's sources traced it to routers in Guangdong and said they did not know whether the spying was official [110].
- **Overstated: the Athens wiretaps as an NSA operation.** That attribution rests on one 2015 press account that draws on Greek prosecutors' material, anonymous former officials and Snowden documents showing capability rather than this tap, with no government admission [112][111].
- **Overstated: round loss figures.** Web Snare's $215 million is an estimate across more than 160 cases, and DOJ ($4 million) and the Secret Service ($4.3 million) give different Shadowcrew figures [69][71][72].
- **Overstated: the precision of ids on 2004 events.** Every ATT&CK, CAPEC and most CWE ids are retrospective; NVD gives a specific CWE for only one of the 2004-era CVEs checked [4][98][99].
- **Understated: exploitation before the fix.** MS04-025 and MS04-040 both say exploitation was already reported at release [18][25].
- **Understated: Witty as a destructive attack on security products.** It is the year's clearest destructive payload, and every victim ran security software [37].
- **Understated: wireless as the intrusion path.** Lowe's, Tereshchuk and the later BJ's complaint all ran through unsecured or weakly secured wireless networks, years before ATT&CK had a Wi-Fi technique [74][61][77].
- **Understated: Snake's operational start.** A nine-agency government record dates Snake's first operations to shortly after early 2004, a stronger record than anything published in 2004 itself [102].
- **Understated: 2004 as a standards year.** FIPS 199, SP 800-61 and SP 800-37 all date from 2004 and get one line each against many for the worms [78][79][82].
- **Understated: defender cost.** No primary opened here puts a figure on remediation or on SP2 uptake [49][50].

### Discrepancies in the record

- **Witty's disclosure date (a date to read carefully).** VU#947254 gives a public date of 8 March; CAIDA says eEye discovered the flaw on 8 March and announced it on 18 March, and Witty began the next day [38][37].
- **The phpBB fix.** TA04-356A says the flaw was fixed in 2.0.11; VU#497400 says 2.0.11 did not fully fix it and the full fix is 2.0.16 [28][27].
- **CVE-2003-0533's dates.** The CVE record was published on 16 April and NVD's on 1 June [12][13].
- **Shadowcrew's arrests and losses.** DOJ reports 21 US arrests and losses over $4 million; the Secret Service reports 28 arrests in eight states and six countries and losses over $4.3 million [71][72].
- **EquationLaser's years.** Kaspersky's Q&A gives both "around 2001-2004" and "around 2001-2003" [113].
- **XP SP2's date.** Released to manufacturing on 6 August; lifecycle start date 17 September [49][51].
- **The FBI technician.** The release's own headline says the technician pleads guilty; its body reports a 12-month sentence on 26 February 2004 after a guilty plea in December 2003 [60].
- **Titan Rain's start.** TIME dates Carpenter's first Titan Rain discoveries to March 2004, after a September 2003 Lockheed Martin break-in [110].

## Sources

All sources were opened on 12 November 2026, apart from the NVD records [128] and [129], opened on 13 November, and the library data checks were run on 13 November 2026. All are checked as of 13 November 2026. Grade is the source's evidence grade as used in this study. Addresses shown as code rather than as links refuse automated link checkers (the three ftc.gov releases, the gao.gov page, the IACR ePrint page and the Sophos research page); copy them into a browser to open them.

| # | Source | URL | Opened | Grade |
|---|---|---|---|---|
| 1 | CMU SEI, "2004 CERT Advisories" (CA-2004-01 and CA-2004-02) | https://www.sei.cmu.edu/documents/511/2004_019_001_496204.pdf | 2026-11-12 | Confirmed |
| 2 | CMU SEI, 2004 CERT Advisories collection page | https://www.sei.cmu.edu/library/2004-cert-advisories/ | 2026-11-12 | Confirmed; Inferred (the end of the series) |
| 3 | CERT/CC, VU#749342 (H.323) | https://kb.cert.org/vuls/id/749342 | 2026-11-12 | Confirmed |
| 4 | NVD, CVE-2003-0819 | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2003-0819 | 2026-11-12 | Confirmed |
| 5 | Microsoft Security Bulletin MS04-007 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2004/ms04-007 | 2026-11-12 | Confirmed |
| 6 | US-CERT SA04-041A (CISA archive) | https://www.cisa.gov/news-events/alerts/2004/02/10/multiple-vulnerabilities-microsoft-windows | 2026-11-12 | Confirmed |
| 7 | NVD, CVE-2003-0818 | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2003-0818 | 2026-11-12 | Confirmed |
| 8 | US-CERT TA04-078A, Multiple Vulnerabilities in OpenSSL | https://www.cisa.gov/news-events/alerts/2004/03/18/multiple-vulnerabilities-openssl | 2026-11-12 | Confirmed |
| 9 | Microsoft Security Bulletin MS04-011 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2004/ms04-011 | 2026-11-12 | Confirmed |
| 10 | US-CERT TA04-104A | https://www.cisa.gov/news-events/alerts/2004/04/13/multiple-vulnerabilities-microsoft-products | 2026-11-12 | Confirmed |
| 11 | CERT/CC, VU#753212 (LSASS) | https://kb.cert.org/vuls/id/753212 | 2026-11-12 | Confirmed |
| 12 | CVE record, CVE-2003-0533 | https://cveawg.mitre.org/api/cve/CVE-2003-0533 | 2026-11-12 | Confirmed |
| 13 | NVD, CVE-2003-0533 | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2003-0533 | 2026-11-12 | Confirmed |
| 14 | US-CERT TA04-111A, Vulnerabilities in TCP | https://www.cisa.gov/news-events/alerts/2004/04/20/vulnerabilities-tcp | 2026-11-12 | Confirmed |
| 15 | US-CERT TA04-147A, CVS Heap Overflow Vulnerability | https://www.cisa.gov/news-events/alerts/2004/05/26/cvs-heap-overflow-vulnerability | 2026-11-12 | Confirmed |
| 16 | CERT/CC, VU#713878 (IE cross-domain redirect) | https://kb.cert.org/vuls/id/713878 | 2026-11-12 | Confirmed |
| 17 | US-CERT TA04-163A | https://www.cisa.gov/news-events/alerts/2004/06/11/cross-domain-redirect-vulnerability-internet-explorer | 2026-11-12 | Confirmed |
| 18 | Microsoft Security Bulletin MS04-025 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2004/ms04-025 | 2026-11-12 | Confirmed; Inferred (the off-cycle reading) |
| 19 | Microsoft Security Bulletin MS04-028 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2004/ms04-028 | 2026-11-12 | Confirmed |
| 20 | US-CERT TA04-260A, Windows JPEG component buffer overflow | https://www.cisa.gov/news-events/alerts/2004/09/16/microsoft-windows-jpeg-component-buffer-overflow | 2026-11-12 | Confirmed |
| 21 | NVD, CVE-2004-0200 | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2004-0200 | 2026-11-12 | Confirmed |
| 22 | NVD, CVE-2004-0597 | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2004-0597 | 2026-11-12 | Confirmed |
| 23 | CERT/CC, VU#842160 (IE FRAME/IFRAME) | https://www.kb.cert.org/vuls/id/842160 | 2026-11-12 | Confirmed |
| 24 | US-CERT TA04-315A | https://www.cisa.gov/news-events/alerts/2004/11/10/buffer-overflow-microsoft-internet-explorer | 2026-11-12 | Confirmed |
| 25 | Microsoft Security Bulletin MS04-040 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2004/ms04-040 | 2026-11-12 | Confirmed |
| 26 | Microsoft Security Bulletin MS04-045 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2004/ms04-045 | 2026-11-12 | Confirmed; Inferred (the bulletin count) |
| 27 | CERT/CC, VU#497400 (phpBB highlight) | https://www.kb.cert.org/vuls/id/497400 | 2026-11-12 | Confirmed |
| 28 | US-CERT TA04-356A | https://www.cisa.gov/news-events/alerts/2004/12/21/exploitation-phpbb-highlight-parameter-vulnerability | 2026-11-12 | Confirmed |
| 29 | CVE record, CVE-2004-1315 | https://cveawg.mitre.org/api/cve/CVE-2004-1315 | 2026-11-12 | Confirmed |
| 30 | NVD, CVE-2004-1315 detail page | https://nvd.nist.gov/vuln/detail/CVE-2004-1315 | 2026-11-12 | Confirmed |
| 31 | NVD, CVE-2004-1315 (API record) | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2004-1315 | 2026-11-12 | Confirmed |
| 32 | US-CERT SA04-028A, MyDoom.B Virus | https://www.cisa.gov/news-events/alerts/2004/01/28/mydoomb-virus | 2026-11-12 | Confirmed |
| 33 | Microsoft, reward offer for the MyDoom.B authors, 29 Jan 2004 | https://news.microsoft.com/source/2004/01/29/microsoft-offers-250000-reward-for-information-leading-to-conviction-of-mydoom-b-perpetrators/ | 2026-11-12 | Confirmed |
| 34 | F-Secure, Bagle description | https://www.f-secure.com/v-descs/bagle.shtml | 2026-11-12 | Confirmed |
| 35 | F-Secure, Novarg (MyDoom) description | https://www.f-secure.com/v-descs/novarg.shtml | 2026-11-12 | Confirmed |
| 36 | US-CERT SA04-079A, Continuing Threats to Home Users | https://www.cisa.gov/news-events/alerts/2004/03/19/continuing-threats-home-users | 2026-11-12 | Confirmed |
| 37 | CAIDA, The Spread of the Witty Worm | https://www.caida.org/archive/witty/ | 2026-11-12 | Confirmed (CAIDA's measurements) |
| 38 | CERT/CC, VU#947254 (ISS PAM) | https://kb.cert.org/vuls/id/947254 | 2026-11-12 | Confirmed |
| 39 | CVE record, CVE-2004-0362 | https://cveawg.mitre.org/api/cve/CVE-2004-0362 | 2026-11-12 | Confirmed |
| 40 | NVD, CVE-2004-0362 | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2004-0362 | 2026-11-12 | Confirmed |
| 41 | Microsoft, reward program and the Sasser arrest, 8 May 2004 | https://news.microsoft.com/source/2004/05/08/microsoft-reward-program-helps-lead-to-information-resulting-in-arrest-related-to-sasser-internet-worm/ | 2026-11-12 | Confirmed; Inferred (the launch date) |
| 42 | Microsoft, Anti-Virus Reward Program, 5 Nov 2003 | https://news.microsoft.com/source/2003/11/05/microsoft-announces-anti-virus-reward-program/ | 2026-11-12 | Confirmed |
| 43 | F-Secure, Sasser description | https://www.f-secure.com/v-descs/sasser.shtml | 2026-11-12 | Confirmed |
| 44 | Microsoft, statement on Download.Ject, 25 Jun 2004 | https://news.microsoft.com/source/2004/06/25/microsoft-statement-regarding-download-ject-malicious-code-security-issue/ | 2026-11-12 | Confirmed |
| 45 | US-CERT SA04-184A, Important Internet Explorer Update Available | https://www.cisa.gov/news-events/alerts/2004/07/02/important-internet-explorer-update-available | 2026-11-12 | Confirmed |
| 46 | US-CERT SA04-208A, New Variant of MyDoom Virus | https://www.cisa.gov/news-events/alerts/2004/07/26/new-variant-mydoom-virus | 2026-11-12 | Confirmed |
| 47 | F-Secure, Cabir description | https://www.f-secure.com/v-descs/cabir.shtml | 2026-11-12 | Confirmed |
| 48 | Microsoft, statement on the posting of Windows 2000 source code, 12 Feb 2004 | https://news.microsoft.com/source/2004/02/12/statement-from-microsoft-regarding-illegal-posting-of-windows-2000-source-code/ | 2026-11-12 | Confirmed |
| 49 | Microsoft, Windows XP SP2 released to manufacturers, 6 Aug 2004 | https://news.microsoft.com/source/2004/08/06/microsoft-releases-windows-xp-service-pack-2-with-advanced-security-technologies-to-computer-manufacturers/ | 2026-11-12 | Confirmed |
| 50 | US-CERT SA04-243A, Security Improvements in Windows XP Service Pack 2 | https://www.cisa.gov/news-events/alerts/2004/08/30/security-improvements-windows-xp-service-pack-2 | 2026-11-12 | Confirmed |
| 51 | Microsoft Lifecycle, Windows XP | https://learn.microsoft.com/en-us/lifecycle/products/windows-xp | 2026-11-12 | Confirmed |
| 52 | Microsoft TechNet archive, memory protection in Windows XP SP2 | https://learn.microsoft.com/en-us/previous-versions/tn-archive/cc700810(v=technet.10) | 2026-11-12 | Confirmed |
| 53 | Microsoft Learn, Data Execution Prevention | https://learn.microsoft.com/en-us/windows/win32/memory/data-execution-prevention | 2026-11-12 | Confirmed |
| 54 | Microsoft, About the Security Development Lifecycle | https://www.microsoft.com/en-us/securityengineering/sdl/about | 2026-11-12 | Confirmed |
| 55 | Mozilla, Firefox 1.0 release notes | https://www.mozilla.org/en-US/firefox/releases/1.0/ | 2026-11-12 | Confirmed |
| 56 | Public Law 108-187 (CAN-SPAM Act), GovInfo | https://www.govinfo.gov/content/pkg/PLAW-108publ187/html/PLAW-108publ187.htm | 2026-11-12 | Confirmed |
| 57 | DOJ, first criminal charges under CAN-SPAM, 29 Apr 2004 | https://www.justice.gov/archive/opa/pr/2004/April/04_crm_281.htm | 2026-11-12 | Confirmed |
| 58 | FTC, first CAN-SPAM Act cases, 29 Apr 2004 | `https://www.ftc.gov/news-events/news/press-releases/2004/04/ftc-announces-first-can-spam-act-cases` | 2026-11-12 | Confirmed |
| 59 | Microsoft, AOL, EarthLink, Microsoft and Yahoo CAN-SPAM lawsuits, 10 Mar 2004 | https://news.microsoft.com/source/2004/03/10/america-online-earthlink-microsoft-and-yahoo-team-up-to-file-first-major-industry-lawsuits-under-new-federal-anti-spam-law/ | 2026-11-12 | Confirmed |
| 60 | DOJ, FBI legal technician sentenced, 26 Feb 2004 | https://www.justice.gov/archive/opa/pr/2004/February/04_crm_120.htm | 2026-11-12 | Confirmed |
| 61 | DOJ CCIPS archive, Tereshchuk plea, 8 Jun 2004 | https://www.justice.gov/archive/criminal/cybercrime/press-releases/2004/tereshchukPlea.htm | 2026-11-12 | Confirmed |
| 62 | DOJ, Operation Fastlink, 22 Apr 2004 | https://www.justice.gov/archive/opa/pr/2004/April/04_crm_263.htm | 2026-11-12 | Confirmed |
| 63 | DOJ, phishing sentence (Hill), May 2004 | https://www.justice.gov/archive/opa/pr/2004/May/04_crm_336.htm | 2026-11-12 | Confirmed |
| 64 | The Register, bookmaker extortion arrests, 21 Jul 2004 | https://www.theregister.com/2004/07/21/cyber_shakedown_taken_down/ | 2026-11-12 | Reported |
| 65 | DOJ, Snipermail and Acxiom indictment, 21 Jul 2004 | https://www.justice.gov/archive/opa/pr/2004/July/04_crm_501.htm | 2026-11-12 | Confirmed |
| 66 | DOJ CCIPS archive, Levine indictment | https://www.justice.gov/archive/criminal/cybercrime/press-releases/2004/levineIndict.htm | 2026-11-12 | Confirmed |
| 67 | DOJ CCIPS archive, Mateias indictment, 4 Aug 2004 | https://www.justice.gov/archive/criminal/cybercrime/press-releases/2004/mateiasIndict.htm | 2026-11-12 | Confirmed |
| 68 | DOJ, Operation Digital Gridlock, 25 Aug 2004 | https://www.justice.gov/archive/opa/pr/2004/August/04_ag_578.htm | 2026-11-12 | Confirmed |
| 69 | DOJ, Operation Web Snare, 26 Aug 2004 | https://www.justice.gov/archive/opa/pr/2004/August/04_crm_583.htm | 2026-11-12 | Confirmed; Reported (the APWG, IC3 and FTC figures it quotes) |
| 70 | FTC, spyware case against Seismic, Smartbot.Net and Wallace, 12 Oct 2004 | `https://www.ftc.gov/news-events/news/press-releases/2004/10/ftc-cracks-down-spyware-operation` | 2026-11-12 | Confirmed |
| 71 | DOJ, Shadowcrew indictment, 28 Oct 2004 | https://www.justice.gov/archive/opa/pr/2004/October/04_crm_726.htm | 2026-11-12 | Confirmed |
| 72 | US Secret Service, Operation Firewall, 28 Oct 2004 | https://www.secretservice.gov/press/releases/2004/10/us-secret-services-operation-firewall-nets-28-arrests-international | 2026-11-12 | Confirmed |
| 73 | Microsoft, Digital PhishNet, 8 Dec 2004 | https://news.microsoft.com/source/2004/12/08/industry-law-enforcement-team-to-launch-digital-phishnet/ | 2026-11-12 | Confirmed |
| 74 | DOJ CCIPS archive, Salcedo sentenced, 15 Dec 2004 | https://www.justice.gov/archive/criminal/cybercrime/press-releases/2004/salcedoSent.htm | 2026-11-12 | Confirmed |
| 75 | DOJ, first Operation Fastlink guilty plea, 22 Dec 2004 (index title only) | https://www.justice.gov/archive/opa/pr/2004/December/04_crm_801.htm | 2026-11-12 | Confirmed |
| 76 | DOJ, December 2004 press release index | https://www.justice.gov/archive/opa/pr/2004/December/ | 2026-11-12 | Confirmed |
| 77 | FTC, BJ's Wholesale Club settlement, 16 Jun 2005 | `https://www.ftc.gov/news-events/news/press-releases/2005/06/bjs-wholesale-club-settles-ftc-charges` | 2026-11-12 | Confirmed; Inferred (the 2004 dating) |
| 78 | NIST, SP 800-61 (2004) | https://csrc.nist.gov/pubs/sp/800/61/final | 2026-11-12 | Confirmed |
| 79 | NIST, FIPS 199 | https://csrc.nist.gov/pubs/fips/199/final | 2026-11-12 | Confirmed |
| 80 | GAO, GAO-04-354 product page | `https://www.gao.gov/products/gao-04-354` | 2026-11-12 | Confirmed |
| 81 | US-Canada Power System Outage Task Force, final report, April 2004 (DOE) | https://www.energy.gov/oe/downloads/blackout-2003-final-report-august-14-2003-blackout-united-states-and-canada-causes-and | 2026-11-12 | Confirmed |
| 82 | NIST, SP 800-37 (2004) | https://csrc.nist.gov/pubs/sp/800/37/final | 2026-11-12 | Confirmed |
| 83 | NIST, SP 800-67 (2004) | https://csrc.nist.gov/pubs/sp/800/67/final | 2026-11-12 | Confirmed |
| 84 | NIST, SP 800-64 Rev. 1 | https://csrc.nist.gov/pubs/sp/800/64/r1/final | 2026-11-12 | Confirmed |
| 85 | NIST, SP 800-72 | https://csrc.nist.gov/pubs/sp/800/72/final | 2026-11-12 | Confirmed |
| 86 | NIST, SP 800-53 (2005) | https://csrc.nist.gov/pubs/sp/800/53/final | 2026-11-12 | Confirmed |
| 87 | Public Law 108-275 (Identity Theft Penalty Enhancement Act), GovInfo | https://www.govinfo.gov/content/pkg/PLAW-108publ275/html/PLAW-108publ275.htm | 2026-11-12 | Confirmed |
| 88 | White House archive, signing remarks, 15 Jul 2004 | https://georgewbush-whitehouse.archives.gov/news/releases/2004/07/20040715-3.html | 2026-11-12 | Confirmed (as the White House states it) |
| 89 | DHS, HSPD-12 | https://www.dhs.gov/homeland-security-presidential-directive-12 | 2026-11-12 | Confirmed |
| 90 | Public Law 108-458 (Intelligence Reform and Terrorism Prevention Act), GovInfo | https://www.govinfo.gov/app/details/PLAW-108publ458 | 2026-11-12 | Confirmed |
| 91 | Council of Europe, Convention on Cybercrime (ETS 185) | https://rm.coe.int/1680081561 | 2026-11-12 | Confirmed (the 2001 date only) |
| 92 | IEEE SA, IEEE 802.11i-2004 | https://standards.ieee.org/ieee/802.11i/3127/ | 2026-11-12 | Confirmed |
| 93 | RFC 3748, Extensible Authentication Protocol | https://www.rfc-editor.org/rfc/rfc3748.txt | 2026-11-12 | Confirmed |
| 94 | RFC 3704, Ingress Filtering for Multihomed Networks | https://www.rfc-editor.org/rfc/rfc3704.txt | 2026-11-12 | Confirmed |
| 95 | RFC 3833, Threat Analysis of the Domain Name System | https://www.rfc-editor.org/rfc/rfc3833.txt | 2026-11-12 | Confirmed |
| 96 | ISO, ISO/IEC 13335-1:2004 | https://www.iso.org/standard/39066.html | 2026-11-12 | Confirmed |
| 97 | IACR ePrint 2004/199, Wang, Feng, Lai and Yu | `https://eprint.iacr.org/2004/199` | 2026-11-12 | Confirmed |
| 98 | MITRE, CWE history | https://cwe.mitre.org/about/history.html | 2026-11-12 | Confirmed |
| 99 | MITRE, About CAPEC | https://capec.mitre.org/about/index.html | 2026-11-12 | Confirmed |
| 100 | FIRST, CVSS v1 archive | https://www.first.org/cvss/v1/ | 2026-11-12 | Confirmed |
| 101 | MITRE, CWE-1392 Use of Default Credentials | https://cwe.mitre.org/data/definitions/1392.html | 2026-11-12 | Confirmed |
| 102 | FBI, NSA, CISA and partners, AA23-129A, Hunting Russian Intelligence "Snake" Malware, 9 May 2023 | https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-129a | 2026-11-12 | Confirmed |
| 103 | MITRE ATT&CK, Uroburos (S0022) | https://attack.mitre.org/software/S0022/ | 2026-11-12 | Confirmed |
| 104 | MITRE ATT&CK, Turla (G0010) | https://attack.mitre.org/groups/G0010/ | 2026-11-12 | Confirmed |
| 105 | MITRE ATT&CK, APT28 (G0007) | https://attack.mitre.org/groups/G0007/ | 2026-11-12 | Confirmed |
| 106 | SecureWorks (Sophos), Threat Group-4127, 16 Jun 2016 | `https://www.sophos.com/en-us/research/threat-group-4127-targets-hillary-clinton-presidential-campaign` | 2026-11-12 | Confirmed |
| 107 | Mandiant, APT1: Exposing One of China's Cyber Espionage Units, February 2013 | https://services.google.com/fh/files/misc/mandiant-apt1-report.pdf | 2026-11-12 | Confirmed; Inferred (2004 WEBC2 use) |
| 108 | MITRE ATT&CK, APT1 (G0006) | https://attack.mitre.org/groups/G0006/ | 2026-11-12 | Confirmed |
| 109 | MITRE ATT&CK, WEBC2 (S0109) | https://attack.mitre.org/software/S0109/ | 2026-11-12 | Confirmed |
| 110 | TIME, "The Invasion of the Chinese Cyberspies", 29 Aug 2005 | https://time.com/archive/6674509/the-invasion-of-the-chinese-cyberspies/ | 2026-11-12 | Reported |
| 111 | IEEE Spectrum, "The Athens Affair", 29 Jun 2007 | https://spectrum.ieee.org/the-athens-affair | 2026-11-12 | Reported |
| 112 | The Intercept, "A Death in Athens", 28 Sep 2015 | https://theintercept.com/2015/09/28/death-athens-rogue-nsa-operation/ | 2026-11-12 | Reported |
| 113 | Kaspersky, "Equation Group: Questions and Answers", February 2015 | https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08064459/Equation_group_questions_and_answers.pdf | 2026-11-12 | Confirmed; Inferred (activity on compile dates) |
| 114 | MITRE ATT&CK, Equation (G0020) | https://attack.mitre.org/groups/G0020/ | 2026-11-12 | Confirmed |
| 115 | Kaspersky GReAT, "Regin: nation-state ownage of GSM networks", 24 Nov 2014 | https://securelist.com/regin-nation-state-ownage-of-gsm-networks/67741/ | 2026-11-12 | Confirmed |
| 116 | MITRE ATT&CK, Darkhotel (G0012) | https://attack.mitre.org/groups/G0012/ | 2026-11-12 | Confirmed |
| 117 | Kaspersky, "The Darkhotel APT", November 2014 | https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08070903/darkhotel_kl_07.11.pdf | 2026-11-12 | Confirmed |
| 118 | MITRE ATT&CK, T1669 Wi-Fi Networks | https://attack.mitre.org/techniques/T1669 | 2026-11-12 | Confirmed |
| 119 | MITRE ATT&CK, T1498 Network Denial of Service | https://attack.mitre.org/techniques/T1498 | 2026-11-12 | Confirmed |
| 120 | TeamStarWolf library, `data/attack/technique_profiles.jsonl` | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/attack/technique_profiles.jsonl | 2026-11-12, 2026-11-13 | Demonstrated |
| 121 | TeamStarWolf library, `data/attack/software.jsonl` and `groups.jsonl` | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/attack/software.jsonl | 2026-11-12, 2026-11-13 | Demonstrated |
| 122 | TeamStarWolf library, `data/attack/superseded_by.jsonl` | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/attack/superseded_by.jsonl | 2026-11-13 | Demonstrated |
| 123 | TeamStarWolf library, `data/attack/d3fend_countermeasures.jsonl` and `technique_to_d3fend.jsonl` | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/attack/d3fend_countermeasures.jsonl | 2026-11-12, 2026-11-13 | Demonstrated |
| 124 | TeamStarWolf library, `data/weaknesses/cwe.jsonl` and `data/weaknesses/capec.jsonl` | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/weaknesses/cwe.jsonl | 2026-11-13 | Demonstrated |
| 125 | TeamStarWolf library, `mitre/` page tree (techniques, groups, software, CAPEC, D3FEND and mitigation pages) | https://github.com/TeamStarWolf/TeamStarWolf/tree/main/mitre | 2026-11-12, 2026-11-13 | Demonstrated |
| 126 | TeamStarWolf library, `navigator/library-layers/chronicle-2016.json` (layer format and scoring scale) | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/chronicle-2016.json | 2026-11-12, 2026-11-13 | Demonstrated |
| 127 | TeamStarWolf library, `case-studies/CYBERCRIME_FOUR_BOOKS.md` (home study) | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/case-studies/CYBERCRIME_FOUR_BOOKS.md | 2026-11-12 | Demonstrated |
| 128 | NVD, CVE-2003-0719 | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2003-0719 | 2026-11-13 | Confirmed |
| 129 | NVD, CVE-2004-0549 | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2004-0549 | 2026-11-13 | Confirmed |

*© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.*

*© The MITRE Corporation. Includes material from the Common Weakness Enumeration (CWE™), used under the CWE Terms of Use. https://cwe.mitre.org/*

*© The MITRE Corporation. Includes material from the Common Attack Pattern Enumeration and Classification (CAPEC™), used under the CAPEC Terms of Use. https://capec.mitre.org/*

*© The MITRE Corporation. Includes material from MITRE D3FEND™, used under the D3FEND Terms of Use. https://d3fend.mitre.org/*

*The terms for every MITRE dataset used here are recorded in [THIRD_PARTY_NOTICES.md](/THIRD_PARTY_NOTICES.md).*

## Related references

- [Notable Incidents](/NOTABLE_INCIDENTS.md), [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [CVE Reference](/CVE_REFERENCE.md)
- [CWE Reference](/CWE_REFERENCE.md), [CAPEC Reference](/CAPEC_REFERENCE.md), [D3FEND Reference](/D3FEND_REFERENCE.md), [Email Security](/EMAIL_SECURITY_REFERENCE.md), [Wireless Security](/WIRELESS_SECURITY_REFERENCE.md), [Cryptography](/CRYPTOGRAPHY_REFERENCE.md), [Supply Chain Security](/SUPPLY_CHAIN_SECURITY.md), [Incident Response](/INCIDENT_RESPONSE_REFERENCE.md), [Vulnerability Root Causes](/VULNERABILITY_ROOT_CAUSES.md), [ICS/OT Security](/ICS_OT_SECURITY_REFERENCE.md), [ICS ATT&CK Atlas](/ICS_ATTACK_ATLAS.md)
- Home studies: [Four Books on Cybercrime](/case-studies/CYBERCRIME_FOUR_BOOKS.md); [The Dot-Com Era](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md); [E-Commerce Threats](/case-studies/ECOMMERCE_THREATS.md); [Kevin Mitnick](/case-studies/MITNICK_INTRUSIONS.md); [Russia-attributed actors](/case-studies/THREAT_ACTORS_RUSSIA.md); [Fancy Bear Goes Phishing](/case-studies/FANCY_BEAR_GOES_PHISHING_CASES.md); [China-attributed actors](/case-studies/THREAT_ACTORS_CHINA.md); [The hacker and the state](/case-studies/HACKER_AND_THE_STATE_CASES.md); [United States actors](/case-studies/THREAT_ACTORS_UNITED_STATES.md); [NSA and CIA tool leaks](/case-studies/NSA_CIA_TOOL_LEAKS.md); [Other states](/case-studies/THREAT_ACTORS_OTHER_STATES.md); [The Zero-Day Market](/case-studies/ZERO_DAY_MARKET_EVENTS.md); [Ransomware ecosystem](/case-studies/RANSOMWARE_ECOSYSTEM.md); [APT41](/case-studies/APT41_PUBLIC_RECORD.md); [Stuxnet](/case-studies/STUXNET.md); [ICS attacks and advisories](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md); [Log4Shell](/case-studies/LOG4SHELL.md); [npm supply-chain attacks](/case-studies/NPM_SUPPLY_CHAIN_ATTACKS.md); [xz Utils backdoor](/case-studies/XZ_UTILS_BACKDOOR_2024.md); [Hugging Face supply chain](/case-studies/HUGGING_FACE_SUPPLY_CHAIN.md); [SolarWinds SUNBURST](/case-studies/SOLARWINDS_SUNBURST.md)
- Series: [1993](/case-studies/CHRONICLE_1993.md), [1994](/case-studies/CHRONICLE_1994.md), [1995](/case-studies/CHRONICLE_1995.md), [1996](/case-studies/CHRONICLE_1996.md), [1997](/case-studies/CHRONICLE_1997.md), [1998](/case-studies/CHRONICLE_1998.md), [1999](/case-studies/CHRONICLE_1999.md), [2000](/case-studies/CHRONICLE_2000.md), [2001](/case-studies/CHRONICLE_2001.md), [2002](/case-studies/CHRONICLE_2002.md), [2016](/case-studies/CHRONICLE_2016.md), [2017](/case-studies/CHRONICLE_2017.md), [2018](/case-studies/CHRONICLE_2018.md), [2019](/case-studies/CHRONICLE_2019.md), [2020](/case-studies/CHRONICLE_2020.md), [2021](/case-studies/CHRONICLE_2021.md), [2022](/case-studies/CHRONICLE_2022.md), [2023](/case-studies/CHRONICLE_2023.md), [2024](/case-studies/CHRONICLE_2024.md), [2025](/case-studies/CHRONICLE_2025.md), [2026](/case-studies/CHRONICLE_2026.md)
- Techniques: [T1566.001 Spearphishing Attachment](/mitre/techniques/T1566-001.md), [T1204.002 Malicious File](/mitre/techniques/T1204-002.md), [T1566.002 Spearphishing Link](/mitre/techniques/T1566-002.md), [T1598.003 Spearphishing Link](/mitre/techniques/T1598-003.md), [T1684.002 Email Spoofing](/mitre/techniques/T1684-002.md), [T1087.003 Email Account](/mitre/techniques/T1087-003.md), [T1105 Ingress Tool Transfer](/mitre/techniques/T1105.md), [T1090 Proxy](/mitre/techniques/T1090.md), [T1584.005 Botnet](/mitre/techniques/T1584-005.md), [T1498 Network Denial of Service](/mitre/techniques/T1498.md), [T1685 Disable or Modify Tools](/mitre/techniques/T1685.md), [T1210 Exploitation of Remote Services](/mitre/techniques/T1210.md), [T1046 Network Service Discovery](/mitre/techniques/T1046.md), [T1190 Exploit Public-Facing Application](/mitre/techniques/T1190.md), [T1189 Drive-by Compromise](/mitre/techniques/T1189.md), [T1203 Exploitation for Client Execution](/mitre/techniques/T1203.md), [T1593.002 Search Engines](/mitre/techniques/T1593-002.md), [T1491.002 External Defacement](/mitre/techniques/T1491-002.md), [T1561.001 Disk Content Wipe](/mitre/techniques/T1561-001.md), [T1669 Wi-Fi Networks](/mitre/techniques/T1669.md), [T1657 Financial Theft](/mitre/techniques/T1657.md), [T1583.001 Domains](/mitre/techniques/T1583-001.md); object techniques [T1014](/mitre/techniques/T1014.md), [T1059.003](/mitre/techniques/T1059-003.md), [T1574.001](/mitre/techniques/T1574-001.md), [T1480.001](/mitre/techniques/T1480-001.md), [T1564.005](/mitre/techniques/T1564-005.md), [T1120](/mitre/techniques/T1120.md), [T1542.002](/mitre/techniques/T1542-002.md)
- CAPEC: [CAPEC-24](/mitre/capec/CAPEC-24.md), [CAPEC-92](/mitre/capec/CAPEC-92.md), [CAPEC-97](/mitre/capec/CAPEC-97.md), [CAPEC-98](/mitre/capec/CAPEC-98.md), [CAPEC-100](/mitre/capec/CAPEC-100.md), [CAPEC-125](/mitre/capec/CAPEC-125.md), [CAPEC-163](/mitre/capec/CAPEC-163.md), [CAPEC-185](/mitre/capec/CAPEC-185.md), [CAPEC-242](/mitre/capec/CAPEC-242.md), [CAPEC-300](/mitre/capec/CAPEC-300.md), [CAPEC-578](/mitre/capec/CAPEC-578.md)
- Groups and software: Turla [G0010](/mitre/groups/G0010.md) and Uroburos [S0022](/mitre/software/S0022.md), for Snake's operating start; APT28 [G0007](/mitre/groups/G0007.md); APT1 [G0006](/mitre/groups/G0006.md) and WEBC2 [S0109](/mitre/software/S0109.md); Equation [G0020](/mitre/groups/G0020.md); Darkhotel [G0012](/mitre/groups/G0012.md); Regin [S0019](/mitre/software/S0019.md), for context
- [Navigator layers](/navigator/index.md), including this study's layer, [chronicle-2004.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/chronicle-2004.json)
