# The Year 2015 in Intrusions: A Dated Record

*A TeamStarWolf case study. Published 13 November 2026; every source checked as of that date.*

[All case studies](/case-studies/README.md) · Related: [Notable Incidents](/NOTABLE_INCIDENTS.md), [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [CVE Reference](/CVE_REFERENCE.md), [Threat Intelligence](/THREAT_INTELLIGENCE_REFERENCE.md), [Cryptography](/CRYPTOGRAPHY_REFERENCE.md), [Web Application Security](/WEB_APPLICATION_SECURITY_REFERENCE.md), [GRC and Compliance](/GRC_COMPLIANCE_REFERENCE.md), [Incident Response](/INCIDENT_RESPONSE_REFERENCE.md), [Vulnerability Management](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [Ransomware Defense](/RANSOMWARE_DEFENSE_REFERENCE.md), [ICS/OT Security](/ICS_OT_SECURITY_REFERENCE.md) · Home studies for events summarized here: [The Hacker and the State](/case-studies/HACKER_AND_THE_STATE_CASES.md) (OPM and the US-China commitment), [China-attributed threat actors](/case-studies/THREAT_ACTORS_CHINA.md) (Anthem), [Sandworm Operations](/case-studies/SANDWORM_OPERATIONS.md) (the Ukrainian grid), [Russia-attributed threat actors](/case-studies/THREAT_ACTORS_RUSSIA.md) (the Bundestag and TV5Monde), [Fancy Bear Goes Phishing](/case-studies/FANCY_BEAR_GOES_PHISHING_CASES.md) (APT29 at the DNC), [The Zero-Day Market](/case-studies/ZERO_DAY_MARKET_EVENTS.md) (Hacking Team), [Stuxnet](/case-studies/STUXNET.md) (Duqu 2.0 and Equation), [United States-attributed threat actors](/case-studies/THREAT_ACTORS_UNITED_STATES.md) (Equation), [E-Commerce Threats](/case-studies/ECOMMERCE_THREATS.md) (FTC v. Wyndham), [ProFTPD mod_copy](/case-studies/PROFTPD_MOD_COPY_CVE_2015_3306.md) (CVE-2015-3306) · Series: [The Year 2014 in Intrusions](/case-studies/CHRONICLE_2014.md), [The Year 2016 in Intrusions](/case-studies/CHRONICLE_2016.md) and the other years in the [case studies index](/case-studies/README.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Threat intelligence analysts, security historians, vulnerability management, ICS, privacy and policy teams and anyone who wants the history behind current threats

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Beginner to intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 73 min (16,874 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want a dated record of the intrusions of 2015, you need OPM, Anthem and the Ukrainian blackout side by side with the year's espionage reports, the implants below the operating system, the exploited Win32k and Flash flaws, the breaches and takedowns that went to court, the laws, norms and standards that followed, or you want the defender lessons that still apply

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [Part 2: the state record](#part-2-the-state-record), [Part 4: below the operating system and into the supply chain](#part-4-below-the-operating-system-and-into-the-supply-chain)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Notable Incidents](/NOTABLE_INCIDENTS.md), [Sandworm: The Operations in the Public Record](/case-studies/SANDWORM_OPERATIONS.md), [The Hacker and the State](/case-studies/HACKER_AND_THE_STATE_CASES.md), [The Year 2014 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2014.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive summary

For the people who ran federal personnel systems, health insurers, banks, newsrooms and power distribution companies, 2015 was the year the intrusion became a public event with a public number attached. Anthem's annual report said it had been the target of a sophisticated external cyber attack that took names, birthdays, health care identification and Social Security numbers of members and employees, and a 2019 indictment, as the FBI's wanted notice records, alleges the theft of data on about 78.8 million persons (Confirmed [1]; Confirmed as charged [3]). The Office of Personnel Management gave public notice on 4 June that personnel records of 4.2 million people were compromised and on 9 July that background-investigation data on more than 20 million people were compromised, after its fingerprint data appear to have left the network around 26 March (Confirmed [26]). On 23 December remote intrusions at three Ukrainian regional power distribution companies cut power to about 225,000 customers, in what ATT&CK calls the first major public attack against the Ukrainian power grid by Sandworm Team, with operators' own breakers opened remotely and the systems wiped afterward (Confirmed [78][131]).

The year's research reports reached back a decade or more. Kaspersky named the Equation group, with command servers registered from 2001 and possibly 1996 and a module that could reprogram hard-drive firmware, and announced Carbanak, a campaign it estimated stole up to USD 1 billion from up to 100 financial institutions (Confirmed [8]; Reported for the estimate [10]). Kaspersky also found Duqu 2.0 inside its own network (Confirmed [38]). FireEye, Kaspersky and Palo Alto Networks published long-running espionage operations against Southeast Asia, and F-Secure assessed that the Dukes had worked for the Russian Federation since at least 2008 (Confirmed [85][87][89][60]). Most of these reports named no state, and the official attributions came later: the UK linked GRU Unit 26165 to the Bundestag and TV5Monde attacks, and France attributed TV5Monde to the GRU only in 2025, and a US indictment named GRU officers for the Ukrainian blackout in 2020 (Confirmed [22][23][81]; Inferred for the reading).

Implants moved below the operating system. Equation's firmware module, a UEFI rootkit tied to Hacking Team, malicious ROMMON images on Cisco routers, the SYNful Knock router implant and unauthorized code in Juniper's ScreenOS were all public by December (Confirmed [8][102][62][63][75]). A trojanized copy of Apple's Xcode put malware into App Store apps (Confirmed [65]).

Governments answered with instruments. The United States sanctioned North Korea over Sony Pictures on 2 January, created a cyber sanctions authority on 1 April, issued an information-sharing order in February, enacted the Cybersecurity Act of 2015 on 18 December and agreed with China in September that neither government would conduct or knowingly support cyber-enabled theft of intellectual property for commercial advantage (Confirmed [5][18][20][105][66]). Europe's highest court invalidated the Safe Harbour decision, a US appeals court upheld the FTC's authority over deficient cybersecurity, and the UN group of governmental experts recommended that states not damage each other's critical infrastructure (Confirmed [107][108][109]). The defender's toolkit also became institutional: MITRE released ATT&CK publicly in May with 96 techniques, the IETF retired RC4 and SSL 3.0, Let's Encrypt issued its first certificate and Microsoft described PowerShell v5 script block logging (Confirmed [126][121][123][124][119]).

This study records the year by date. It is built from sources opened on 12 and 13 November 2026 and from checks of the library's data run on the same days, and is checked as of 13 November 2026.

### Key facts at a glance

| Field | Value |
|---|---|
| Period | 1 January to 31 December 2015, plus the records that open, close or explain a 2015 event: Equation infrastructure from 1996 and 2001, the 2014 OPM and Anthem footholds, the 2016 House timeline and privacy commissioners' report, the 2018, 2019 and 2020 charging documents, the 2021 ICS alert update, France's 2025 attribution and KEV additions from 2021 to 2026 |
| Largest data thefts | Anthem, about 78.8 million persons, as charged (Feb 2014 to Jan 2015); OPM, 4.2 million personnel records and more than 20 million background-investigation records; Ashley Madison, about 36 million accounts; TalkTalk, 156,959 customers; IRS Get Transcript, about 100,000 accounts (Confirmed [3][26][46][69][110]) |
| Grid blackout | 23 December: three Ukrainian distribution companies, about 225,000 customers; six organizations intruded; ATT&CK campaign C0028 (Confirmed [78][79]) |
| State and espionage reports | Equation (16 Feb); APT30 (Apr); Naikon (14 May); Duqu 2.0 (10 Jun); Lotus Blossom (16 Jun); HAMMERTOSS (Jul); Satellite Turla (9 Sep); the Dukes (Sep) (Confirmed [8][85][87][38][89][58][83][60]) |
| Below the operating system | Equation hard-drive firmware (Feb); Hacking Team UEFI rootkit (Jul); Cisco ROMMON images (12 Aug); SYNful Knock (15 Sep); ScreenOS unauthorized code (17 Dec) (Confirmed [8][102][62][63][75]) |
| Crime and takedowns | Carbanak (17 Feb); Simda (15 Apr); CryptoWall (23 Jun); Darkode (15 Jul); newswire hack charges (11 Aug); Dridex (13 Oct); Dorkbot (3 Dec); Ulbricht convicted (4 Feb) and sentenced to life (29 May) (Confirmed [10][25][40][94][61][67][74][93]) |
| Named flaws | GHOST CVE-2015-0235; FREAK CVE-2015-0204; HTTP.sys CVE-2015-1635; VENOM CVE-2015-3456; Logjam CVE-2015-4000; Flash CVE-2015-5119 and CVE-2015-5122; Stagefright; WebLogic deserialization CVE-2015-4852; ScreenOS CVE-2015-7755 and CVE-2015-7756 (Confirmed [6][13][29][35][36][43][52][72][77]) |
| KEV tail | 48 CVE-2015 entries in the catalog downloaded 12 Nov 2026, added from 2021-11-03 to 2026-10-08; four flagged for known ransomware use (Confirmed [99]) |
| Policy and standards | EO 13691 (13 Feb); EO 13694 (1 Apr); Wassenaar proposed rule (20 May); Sprint (12 Jun); UN GGE (22 Jul); Wyndham (24 Aug); US-China (25 Sep); Schrems (6 Oct); Cybersecurity Act of 2015 (18 Dec); RFC 7465, 7525 and 7568; NIST SP 800-161, 800-82 Rev. 2 and 800-171 (Confirmed [20][18][104][113][109][108][66][107][105][121][122][123][114][115][116]) |
| This study's MITRE binding | 57 ATT&CK Enterprise techniques in 75 technique-tactic entries (45 listed by ATT&CK for an object tied to a 2015 report or event, 9 described by a primary and assigned here, 3 Inferred); 20 ATT&CK for ICS techniques from C0028; CWE ids from NVD; CAPEC and D3FEND pairings from the library's data; one Enterprise and one ICS Navigator layer (Part 9) |

### Key findings

- **The thefts were measured in tens of millions.** Anthem, OPM and Ashley Madison each lost data on millions of people, and OPM's background-investigation loss alone covered more than 20 million (Confirmed [3][26][46]).
- **Industrial disruption crossed from report to outage.** The Ukrainian attackers used remote administration tools and ICS client software over VPN, likely with legitimate credentials, then wiped systems and corrupted serial-to-Ethernet firmware (Confirmed [78]).
- **Attribution lagged the events by years.** OPM's primary record names no actor; the Ukrainian alert named no attacker until a 2021 update; the Bundestag and TV5Monde attributions came from the UK profile and France's 2025 statement (Confirmed [26][78][22][23]; Inferred for the reading).
- **Tradecraft went below the operating system.** Disk firmware, system firmware, router images and a firewall's own code were all reported in one year, and the library's D3FEND data maps nothing to the router-image and network-device-authentication techniques (Confirmed [8][102][62][63][75]; Demonstrated [133]).
- **Credentials and remote access were the common door.** Ashley Madison's attacker likely used a compromised employee's valid credentials over a single-factor VPN, OPM's adversary used a contractor's credentials, and the Ukrainian operators came in over VPN (Confirmed [46][26][78]).
- **Business email compromise outweighed ransomware by money.** IC3 counted over USD 263 million in BEC losses against over USD 1.6 million for ransomware in 2015 complaints (Confirmed [82]).
- **The branded bugs and the exploited bugs were again different lists.** FREAK, Logjam, GHOST, VENOM and CVE-2015-1538 are not in KEV, while Win32k CVE-2015-1701 was exploited in April 2015 and is flagged for known ransomware use (Confirmed [14][36][7][35][53][31][99]).
- **2015 was ATT&CK's public year, but no 2015 event was mapped at the time.** ATT&CK was released in May with 96 techniques; every id in this study is a later binding (Confirmed [126]; Inferred for the binding).

### Top recommendations

1. **Put multi-factor authentication on every VPN and remote-administration path.** The Ukrainian and Ashley Madison intrusions both likely came through remote access with valid credentials, and the ICS alert names controlled remote access with MFA as a mitigation (Confirmed [78][46]).
2. **Plan for a wiper after the intrusion, not only for the intrusion.** KillDisk wiped files and boot records at the end of the Ukrainian attack, and UPS disconnects were scheduled (Confirmed [78]).
3. **Verify firmware and network-device images.** Equation reprogrammed disk firmware, and Cisco and Mandiant described malicious ROMMON and router images (Confirmed [8][62][63]).
4. **Treat vendor code as an attack path.** Juniper found unauthorized code in ScreenOS, and XcodeGhost rode a developer tool into the App Store (Confirmed [75][65]).
5. **Patch internet-facing Java middleware and web applications first.** WebLogic CVE-2015-4852 was remotely exploitable without authentication, and TalkTalk's database was reached by SQL injection through legacy pages, and its database software lacked a fix that had been available for over three and a half years (Confirmed [72][69]).
6. **Retire export-grade and legacy cryptography.** FREAK and Logjam abused export suites, and RFC 7525 and RFC 7568 told implementers to stop negotiating RC4, SSLv2 and SSLv3 (Confirmed [13][37][122][123]).
7. **Turn on script logging.** The PowerShell team described script block logging and enhanced transcription in PowerShell v5 and KB 3000850 on 9 June 2015 (Confirmed [119]).
8. **Give each machine its own local administrator password.** Microsoft LAPS stores a unique random password per domain-joined computer (Confirmed [120]).
9. **Read KEV dates as catalog dates.** ScreenOS CVE-2015-7755 entered KEV on 2 October 2025 and ProFTPD CVE-2015-3306 on 8 October 2026 (Confirmed [99][101]).
10. **Watch for phishing that follows a breach announcement.** US-CERT warned of domains impersonating OPM and its identity-protection contractor after the OPM notice (Confirmed [41]).

## Scope and method

This study covers intrusions, malware, denial of service, vulnerabilities, data breaches, crimeware and takedowns, prosecutions, state and espionage operations, industrial-control incidents, connected vehicles and phones, and regulation, standards and policy dated to 2015, plus the later records that open, close or explain a 2015 event. It follows the method of the [case studies collection](/case-studies/README.md): primary sources first, every claim graded, and numbers given as the source states them. External sources were opened on 12 and 13 November 2026, as the Sources table shows, and the library data checks were run on the same days. The Intelligence Hub's 2015 history shards were used only as an index of dated rows; each fact cited here comes from the primary that a row points to.

| Grade | Meaning in this study |
|---|---|
| Confirmed | The primary record was opened and states the fact: a vendor advisory, bulletin or research report stated as its own finding, a company's own statement or SEC filing, a CERT/CC, US-CERT, ICS-CERT or CISA record, a CVE or NVD record, the KEV catalog, an FBI, IC3, SEC, FTC, IRS or NHTSA record, a court opinion, complaint or indictment (as charged), a public law, a White House, Federal Register, Treasury, UK, French, EU, UN or privacy-commissioner record, a NIST, IETF or MITRE record, a live ATT&CK page or the library's ATT&CK data for what ATT&CK records, or a library study, only for the fact that it is the home for an event |
| Reported | Only a secondary source supports the fact, a source relays someone else's claim without the original being opened here, or a vendor's figure is the vendor's own estimate: Wired on Hacking Team, the Jeep and Ashley Madison, the BBC on TV5Monde and TalkTalk, CrowdStrike's relay of the Bundestag and TV5Monde linkage, ATT&CK's Deep Panda and Naikon attributions where they rest on vendor reports not opened here, Kaspersky's Carbanak loss estimate, the Logjam researchers' estimates and a researcher's comment naming Duqu 2.0's zero-day. The source is named in the text |
| Demonstrated | A check this study ran itself and saw the result: id, name, tactic, CAPEC, CWE, D3FEND and page checks in the library's data files and `mitre/` tree |
| Inferred | The study's own reading, labelled where it appears. Every ATT&CK, CAPEC and D3FEND id bound to a 2015 event is Inferred as to the binding unless ATT&CK lists it for the object, and so is every CWE that NVD does not list |

Charges, complaints and indictments are allegations; where this study cites one, the record confirms that the charge was made, not that it was proven. Company statements are the company's own account, and vendor and researcher attributions are those authors' assessments, not government findings.

Limits a reader should know:

- **CVE existed; ATT&CK was new and unmapped; KEV did not exist.** Every 2015 product flaw here carries a CVE id, and the first ids in the CVE program's new syntax, with four or more sequence digits, were issued on 13 January 2015 (Confirmed [128]). MITRE built its first ATT&CK model in September 2013 and released it publicly in May 2015 with 96 techniques; ATT&CK's own version history starts at v1.0 on 16 January 2018 and does not list that release (Confirmed [126][127]). No 2015 event was mapped to ATT&CK at the time, so every technique id in Part 9 is a later binding, and the ICS ids for the Ukrainian attack have themselves been revised (Confirmed [126][131]; Inferred for the binding). KEV's CVE-2015 entries were added from November 2021 on (Confirmed [99]).
- **Some events have no ATT&CK object or no technique detail.** Anthem's primaries describe no intrusion method; the Bundestag, TV5Monde, VTech and Hacking Team records opened here describe none either; the IRS record says only that taxpayer data from non-IRS sources was used to pass its authentication, which this study does not bind; Simda, Dorkbot, CryptoWall and Superfish have no ATT&CK Enterprise object that this study binds, and XcodeGhost is an ATT&CK for Mobile object (S0297 in the library's mobile data), which this study does not bind (Confirmed [1][3][22][110][42]; Reported [111]; Demonstrated [131]).
- **What was not checked.** The original publication date of the Ukrainian ICS alert (the page shows none; its id implies 25 February 2016, which is Inferred) [78]; the Secureworks TG-3390 page and DGI's Project CameraShy PDF (it returned 404), so ATT&CK's citations of them are relayed [90][88]; the Department of Justice release charging the Dridex administrator [67]; OPM's own notices from that year, whose addresses returned 404 [134]; the full text of the House majority report beyond its title page [27]; the original 2015 release date of Microsoft LAPS [120]; whether CERT/CC's note for CVE-2015-5122 names Hacking Team [43]; the citations behind S0384, S0607 and G0016's technique entries [131]; Anthem's intrusion method; how Hacking Team's network was breached; and the executive order numbers on the White House pages, which print none (the Federal Register gives them) [17][19]. Their absence here is not evidence that nothing happened.

## Part 1: the year as a dated timeline

One row per event or report. The date is the event date where the source gives one, otherwise the publication date. Rows marked "frame" or "boundary" open or close a 2015 event.

| Date | Event | Thread | Sector | Grade | Sources |
|---|---|---|---|---|---|
| 1996 to 2002 (frame) | Equation command servers registered possibly as early as 1996 and in August 2001; samples compiled in 2002 | Espionage | Multiple | Confirmed (vendor's finding) | [8] |
| 2005 to 2010 (frame) | APT30 active since at least 2005; Turla's use of satellite links dates from 2007; the Dukes working since at least 2008; Naikon since at least 2010 | Espionage | Government; military | Confirmed (vendors' findings) | [85][83][60][87] |
| 2008 to 2009 (frame) | Three Wyndham breaches; card data of more than 619,000 consumers taken. Home: [E-Commerce Threats](/case-studies/ECOMMERCE_THREATS.md) | Breach | Hospitality | Confirmed | [108] |
| 2012-07 (frame) | First known adversarial access to OPM | Espionage | Federal government | Confirmed | [26] |
| 2013 (frame) | Carbanak attacks on banks begin; R.T. Jones web server hacked (July 2013) | Crimeware; Breach | Finance | Confirmed | [10][112] |
| 2014 (frame) | OPM foothold with a background-investigation contractor's credentials (7 May) and an RDP session (June); opmsecurity.org registered (April); Anthem intrusion begins (February); Superfish shipped on Lenovo PCs from September | Espionage; Consumer PCs | Federal government; Health insurance; Consumer | Confirmed; as charged for the Anthem start date | [26][3][12] |
| 2015-01-02 | Treasury announces a new Executive Order authorizing sanctions on the North Korean government and the Workers' Party of Korea, citing the Sony Pictures attack | Policy | Government | Confirmed | [5] |
| 2015-01-09 | NVD publishes FREAK, CVE-2015-0204 | Vulnerability | Cross-sector | Confirmed | [14] |
| 2015-01-13 | First new-syntax CVE ids issued; MS15-001, the year's first bulletin | Standards; Vulnerability | Cross-sector | Confirmed | [128][95] |
| 2015-01-13 to 2015-02-04 | Ulbricht trial; convicted on all seven counts | Courts | Online markets | Confirmed | [93] |
| 2015-01-27 to 2015-01-28 | Qualys GHOST advisory (27 Jan); NVD publishes CVE-2015-0235 (28 Jan) | Vulnerability | Cross-sector (Linux) | Confirmed | [6][7] |
| 2015-02 | Anthem reports that it was the target of a sophisticated external cyber attack; RFC 7465 prohibits RC4. Home for Anthem: [China-attributed threat actors](/case-studies/THREAT_ACTORS_CHINA.md) | Breach; Standards | Health insurance; Internet | Confirmed | [1][121] |
| 2015-02-10 | MS15-011, Group Policy remote code execution, Critical | Vulnerability | Cross-sector | Confirmed | [96] |
| 2015-02-13 | Executive Order 13691 on information sharing signed (published 20 Feb) | Policy | Critical infrastructure | Confirmed | [19][20] |
| 2015-02-16 | Kaspersky names the Equation group | Espionage | Multiple | Confirmed (vendor's finding) | [8] |
| 2015-02-17 | Kaspersky, with INTERPOL and Europol, announces Carbanak | Crimeware | Finance | Confirmed (vendor's finding); Reported (loss estimate) | [10] |
| 2015-02-18 to 2015-02-24 | Anthem 8-K exhibit (18 Feb) and 10-K (24 Feb) | Breach | Health insurance | Confirmed | [2][1] |
| 2015-02-20 | US-CERT TA15-051A on Superfish | Vulnerability | Consumer PCs | Confirmed | [12] |
| 2015-02 to 2015-05 | About 200,000 attempts against the IRS Get Transcript application | Breach | Federal government | Confirmed | [110] |
| 2015-03-05 to 2015-03-06 | Microsoft Security Advisory 3046015 (5 Mar); US-CERT FREAK alert (6 Mar) | Vulnerability | Cross-sector | Confirmed | [13] |
| 2015-03-26 | OPM fingerprint data exfiltrated on or around this date; GitHub's largest DDoS begins about 02:00 UTC | Espionage; DDoS | Federal government; Technology | Confirmed | [26][15] |
| 2015-04 | FireEye's APT30 report | Espionage | Government; commercial (Southeast Asia, India) | Confirmed (vendor's finding) | [85] |
| 2015-04 to 2015-05 | German Bundestag attacked; data stolen; Chancellor's and MPs' email affected | Espionage | Parliament | Confirmed (UK government's attribution) | [22] |
| 2015-04-01 | Executive Order 13694, cyber sanctions | Policy | Government | Confirmed | [17][18] |
| 2015-04-08 | TV5Monde: all 12 channels off air at 20:40; NIST SP 800-161 | Destructive; Standards | Media; Federal | Reported (event detail); Confirmed (later attribution; SP 800-161) | [21][22][23][114] |
| 2015-04-10 | Citizen Lab identifies the Great Cannon | DDoS | Technology | Confirmed (researchers' finding) | [16] |
| 2015-04-14 | MS15-034 and NVD CVE-2015-1635 (HTTP.sys) | Vulnerability | Cross-sector (Windows) | Confirmed | [29][30] |
| 2015-04-15 | OPM notifies US-CERT of traffic to opmsecurity.org; US-CERT TA15-105A on the Simda takedown | Espionage; Takedown | Federal government; Consumer | Confirmed | [26][25] |
| 2015-04-21 | NVD publishes Win32k CVE-2015-1701, exploited in the wild in April 2015 | Vulnerability | Cross-sector | Confirmed | [31] |
| 2015-04-23 | OPM declares a major incident for personnel records (Congress notified 30 Apr) | Espionage | Federal government | Confirmed | [26] |
| 2015-04-29 | US-CERT TA15-119A, Top 30 Targeted High Risk Vulnerabilities | Vulnerability management | Critical infrastructure | Confirmed | [97] |
| 2015-05 | ATT&CK released publicly with 96 techniques; RFC 7525 (BCP 195); NIST SP 800-82 Rev. 2 | Standards | Cross-sector; ICS | Confirmed | [126][122][115] |
| 2015-05-12 | MS15-051 fixes CVE-2015-1701 | Vulnerability | Cross-sector | Confirmed | [32] |
| 2015-05-13 | NVD publishes VENOM, CVE-2015-3456 | Vulnerability | Cloud and virtualization | Confirmed | [35] |
| 2015-05-14 | Kaspersky's Naikon report | Espionage | Government (South China Sea region) | Confirmed (vendor's finding) | [87] |
| 2015-05-18 | NVD publishes ProFTPD CVE-2015-3306. Home: [ProFTPD mod_copy](/case-studies/PROFTPD_MOD_COPY_CVE_2015_3306.md) | Vulnerability | Web hosting | Confirmed | [101] |
| 2015-05-20 to 2015-05-21 | Logjam made public (20 May), NVD record (21 May); BIS proposed Wassenaar intrusion rule (20 May); OPM major incident for background investigations (20 May, Congress 27 May) | Vulnerability; Policy; Espionage | Internet; Security vendors; Federal government | Confirmed | [37][36][104][26] |
| 2015-05-26 | IRS announces that about 100,000 Get Transcript accounts were accessed; the application had been shut down temporarily the week before | Breach | Federal government | Confirmed | [110] |
| 2015-05-29 | Ulbricht sentenced to life imprisonment | Courts | Online markets | Confirmed | [93] |
| 2015-06 | RFC 7568 deprecates SSL 3.0 | Standards | Internet | Confirmed | [123] |
| 2015-06-04 | OPM public notice: 4.2 million personnel records | Espionage | Federal government | Confirmed | [26] |
| 2015-06-09 | PowerShell team on script block logging and AMSI | Defense | Cross-sector | Confirmed | [119] |
| 2015-06-10 | Kaspersky discloses Duqu 2.0 | Espionage | Security vendor; diplomacy | Confirmed (vendor's finding) | [38] |
| 2015-06-12 | Federal 30-day Cybersecurity Sprint launched | Policy | Federal government | Confirmed | [113] |
| 2015-06-16 | Unit 42's Operation Lotus Blossom | Espionage | Government; military (Southeast Asia) | Confirmed (vendor's finding) | [89] |
| 2015-06-18 | NIST SP 800-171 | Standards | Contractors | Confirmed | [116] |
| 2015-06-23 | IC3 alert on CryptoWall, relayed by US-CERT | Crimeware | Cross-sector | Confirmed | [40] |
| 2015-06-30 | US-CERT on phishing domains impersonating OPM and CSID | Phishing | Federal employees | Confirmed | [41] |
| 2015-07 | FireEye's HAMMERTOSS report | Espionage | Government | Confirmed (vendor's finding) | [58] |
| 2015-07-05 | Hacking Team's internal trove, about 400 GB, published. Home: [The Zero-Day Market](/case-studies/ZERO_DAY_MARKET_EVENTS.md) | Breach; Zero-day market | Surveillance vendor | Reported (size); Confirmed (CERT/CC public date) | [42][44] |
| 2015-07-07 to 2015-07-08 | CERT/CC VU#561288 (7 Jul) and NVD (8 Jul) on Flash CVE-2015-5119 | Vulnerability | Cross-sector | Confirmed | [44][43] |
| 2015-07-09 | OPM public notice: background-investigation data on more than 20 million people. Home: [The Hacker and the State](/case-studies/HACKER_AND_THE_STATE_CASES.md) | Espionage | Federal government | Confirmed | [26] |
| 2015-07-12 to 2015-07-15 | Ashley Madison: unusual database activity (12 Jul), the attacker's notice (13 Jul), the Impact Team's announcement (15 Jul) | Breach | Consumer web | Confirmed | [46] |
| 2015-07-13 | Trend Micro reference that ATT&CK cites for the Hacking Team UEFI Rootkit | Implant | Surveillance vendor | Confirmed (what ATT&CK records) | [102] |
| 2015-07-14 | NVD publishes Flash CVE-2015-5122; Windows Server 2003 extended support ends | Vulnerability | Cross-sector | Confirmed | [43][117] |
| 2015-07-15 | Darkode forum takedown, Operation Shrouded Horizon | Takedown | Criminal forums | Confirmed | [94] |
| 2015-07-17 | First of two earlier SQL injection attacks on TalkTalk | Breach | Telecom | Confirmed | [69] |
| 2015-07-20 | MS15-078, out of band; Avid Life Media confirms the breach and reports to the OPC | Vulnerability; Breach | Cross-sector; Consumer web | Confirmed | [45][46] |
| 2015-07-21 | Wired on the remote Jeep demonstration; Stagefright made public (VU#924951) | Vehicles; Vulnerability | Automotive; Mobile | Reported (Wired); Confirmed (CERT/CC) | [49][52] |
| 2015-07-22 | UN GGE report A/70/174 | Policy | Government | Confirmed | [109] |
| 2015-07-23 | NHTSA receives recall 15V-461 for 1,416,903 FCA vehicles | Vehicles | Automotive | Confirmed | [50] |
| 2015-07-27 to 2015-07-28 | US-CERT on the Uconnect vulnerability (27 Jul) and Stagefright (28 Jul) | Vehicles; Vulnerability | Automotive; Mobile | Confirmed | [48][51] |
| 2015-07-29 | Windows 10 version 1507 released; MS15-078 re-released for Windows 10 | Defense; Vulnerability | Cross-sector | Confirmed | [118][45] |
| 2015-07-31 | IC3 alert on DDoS extortion campaigns | Crimeware | US businesses | Confirmed | [55] |
| 2015 (summer) | APT29 enters a US political party's systems. Home: [Fancy Bear Goes Phishing](/case-studies/FANCY_BEAR_GOES_PHISHING_CASES.md) | Espionage | Political | Confirmed | [56][24][57] |
| 2015-08-05 | Dell SecureWorks report on Threat Group-3390, as ATT&CK cites it | Espionage | Multiple | Confirmed (what ATT&CK records) | [90] |
| 2015-08-10 to 2015-08-11 | SEC complaint filed under seal (10 Aug) and announced (11 Aug) against 32 defendants in the newswire hacking scheme | Courts | Finance | Confirmed (as charged) | [61] |
| 2015-08-12 | US-CERT on malicious ROMMON images on Cisco IOS devices | Implant | Network infrastructure | Confirmed | [62] |
| 2015-08-13 | Android Security Bulletin, August 2015 | Vulnerability | Mobile | Confirmed | [54] |
| 2015-08-18 to 2015-08-20 | MS15-093 out of band, exploited at release (18 Aug); Ashley Madison data published (18 and 20 Aug) | Vulnerability; Breach | Cross-sector; Consumer web | Confirmed | [98][46] |
| 2015-08-24 | Third Circuit decides FTC v. Wyndham | Courts | Hospitality | Confirmed | [108] |
| 2015-08-25 | FCA recall remedy begins | Vehicles | Automotive | Confirmed | [50] |
| 2015-09-02 to 2015-09-03 | Second earlier SQL injection attack on TalkTalk | Breach | Telecom | Confirmed | [69] |
| 2015-09-09 | Kaspersky's Satellite Turla | Espionage | Government | Confirmed (vendor's finding) | [83] |
| 2015-09-14 | Let's Encrypt issues its first certificate | Standards | Internet | Confirmed | [124] |
| 2015-09-15 | Mandiant reports SYNful Knock | Implant | Network infrastructure | Confirmed (vendor's finding) | [63] |
| 2015-09-17 | Unit 42 reports XcodeGhost; F-Secure's Dukes report, as ATT&CK dates it | Supply chain; Espionage | Mobile; Government | Confirmed | [65][59][60] |
| 2015-09-22 | SEC settles with R.T. Jones over missing written cybersecurity policies | Policy | Finance | Confirmed | [112] |
| 2015-09-23 | Project CameraShy on Naikon, as ATT&CK cites it | Espionage | Government | Reported | [88] |
| 2015-09-25 | US-China commitment on commercial IP theft. Home: [The Hacker and the State](/case-studies/HACKER_AND_THE_STATE_CASES.md) | Policy | Government | Confirmed | [66] |
| 2015-10-01 | NVD publishes Stagefright CVE-2015-1538 | Vulnerability | Mobile | Confirmed | [53] |
| 2015-10-06 | CJEU invalidates the Safe Harbour decision (Schrems) | Courts | Cross-sector | Confirmed | [107] |
| 2015-10-13 | US-CERT TA15-286A on Dridex; the Logjam paper presented at ACM CCS | Crimeware; Vulnerability | Finance; Internet | Confirmed | [67][37] |
| 2015-10-15 to 2015-10-22 | SQL injection against TalkTalk's legacy Tiscali pages (15 to 21 Oct); sites down (21 Oct); ICO notified (22 Oct) | Breach | Telecom | Confirmed | [69] |
| 2015-10-30 | OMB M-16-04, Cybersecurity Strategy and Implementation Plan | Policy | Federal government | Confirmed | [113] |
| 2015-11 | VTech learns from a journalist that its network had been accessed | Breach | Consumer devices; children | Reported | [111] |
| 2015-11-10 | US-CERT TA15-314A on web shells; CAPEC 2.7; Windows 10 version 1511 | Defense; Standards | Cross-sector | Confirmed | [70][130][118] |
| 2015-11-13 | US-CERT on the Apache Commons Collections deserialization flaw | Vulnerability | Cross-sector (Java) | Confirmed | [71] |
| 2015-11-18 | NVD publishes WebLogic CVE-2015-4852 | Vulnerability | Cross-sector (Java) | Confirmed | [73] |
| 2015-12 | Unauthorized SWIFT messages from a Vietnamese bank (as alleged); Patchwork first observed; Joomla CVE-2015-8562 exploited in the wild | Crime and courts; Espionage; Vulnerability | Finance; Government; Web | Confirmed (as charged, for the bank) | [91][131][100] |
| 2015-12-03 | US-CERT TA15-337A on Dorkbot; Let's Encrypt public beta | Takedown; Standards | Consumer; Internet | Confirmed | [74][125] |
| 2015-12-07 | CWE 2.9 and CAPEC 2.8 | Standards | Software | Confirmed | [129][130] |
| 2015-12-08 | MS15-135, the year's last bulletin | Vulnerability | Cross-sector | Confirmed | [95] |
| 2015-12-17 | Juniper's out-of-band ScreenOS advisory; CERT/CC VU#640184 | Implant; Vulnerability | Network infrastructure | Confirmed | [75][76] |
| 2015-12-18 | Public Law 114-113 enacted, with the Cybersecurity Act of 2015 | Policy | Cross-sector | Confirmed | [105] |
| 2015-12-19 | NVD publishes CVE-2015-7755 and CVE-2015-7756 | Vulnerability | Network infrastructure | Confirmed | [77] |
| 2015-12-23 | Three Ukrainian distribution companies lose power to about 225,000 customers. Home: [Sandworm Operations](/case-studies/SANDWORM_OPERATIONS.md) | ICS; Destructive | Energy | Confirmed | [78][79][81] |
| 2015 (full year) | IC3: 288,012 complaints and USD 1,070,711,522 in reported losses | Crime | Cross-sector | Confirmed | [82] |
| 2016 to 2026 (boundary) | ICS alert (id implies 25 Feb 2016); DHS certifies Automated Indicator Sharing (Mar 2016); privacy commissioners' Ashley Madison report (22 Aug 2016); House OPM report (7 Sep 2016); JAR-16-20296A (29 Dec 2016); TalkTalk fine settled (1 Nov 2016); VTech settlement (8 Jan 2018); Park complaint (8 Jun 2018); Anthem indictment (7 May 2019); GRU indictment (15 Oct 2020); AA20-239A (26 Aug 2020); ICS alert's attribution update (20 Jul 2021); France's TV5Monde statement (29 Apr 2025); KEV additions (Nov 2021 to Oct 2026) | Boundary | Cross-sector | Confirmed; Inferred (the alert's date); Reported (the VTech settlement) | [78][106][46][28][56][69][111][91][3][81][92][23][99] |

## Part 2: the state record

### OPM (summary; home: The Hacker and the State)

The House Oversight committee's timeline records the arc. The first known adversarial access was in July 2012; on 7 May 2014 an adversary gained a foothold with a background-investigation contractor's credentials and in June 2014 ran an RDP session; fingerprint data appear to have been exfiltrated on or around 26 March 2015; on 15 April 2015, alerted by a contractor, OPM notified US-CERT of suspicious traffic to opmsecurity.org, a domain registered in April 2014 under the alias "Steve Rogers" that last beaconed in March 2015 (Confirmed [26]). OPM declared a major incident for personnel records on 23 April (Congress notified 30 April) and for background-investigation data on 20 May (Congress notified 27 May), and gave public notice of 4.2 million personnel records on 4 June and of background-investigation data on more than 20 million people on 9 July (Confirmed [26]). The timeline names no actor, and the committee's landing page for its majority staff report of 7 September 2016 attributes the breach only to "a foreign adversary" (Confirmed [26][28]). US-CERT warned on 30 June of phishing domains impersonating OPM and its identity-protection contractor CSID (Confirmed [41]). The federal 30-day Cybersecurity Sprint began on 12 June (Part 7). The home for the OPM record is [The Hacker and the State](/case-studies/HACKER_AND_THE_STATE_CASES.md), and [China-attributed threat actors](/case-studies/THREAT_ACTORS_CHINA.md) also carries it (Confirmed [135][134]).

### Anthem (summary; home: China-attributed threat actors)

Anthem's annual report, filed on 24 February, says that in February 2015 it reported being the target of a sophisticated external cyber attack that obtained names, birthdays, health care identification and Social Security numbers, addresses and income data of current and former members and employees, that the extent was still being determined, and that it was supporting federal law enforcement; an 8-K exhibit of 18 February lists the investigations, claims and litigation as a forward-looking risk (Confirmed [1][2]). The FBI's wanted notice for Fujie Wang says a 7 May 2019 indictment in the Southern District of Indiana charges two alleged members of a hacking group operating in China with stealing data on about 78.8 million persons from a large Indiana health benefits company between February 2014 and January 2015; the page alleges no state direction (Confirmed as charged [3]). ATT&CK says the Anthem intrusion has been attributed to Deep Panda ([G0009](/mitre/groups/G0009.md)), probably also Black Vine, resting on ThreatConnect's reporting of 27 February 2015; the indictment names no group (Reported [4][131]). [China-attributed threat actors](/case-studies/THREAT_ACTORS_CHINA.md) is the home for the figure and the attribution (Confirmed [135]).

### Russia: the Bundestag, TV5Monde and the Dukes

**The Bundestag.** The UK government's GRU profile says the Bundestag was attacked in April and May 2015, a significant amount of data was stolen and email accounts of the Chancellor and other MPs were affected, under the heading that widespread credible evidence indicates these incidents are linked to GRU Unit 26165 (Confirmed [22]).

**TV5Monde.** On 8 April at 20:40 local time all 12 of TV5Monde's channels went off air, and a group calling itself the Cyber Caliphate first claimed responsibility; the BBC reported in October 2016 that the director-general was later told evidence linked the attack to the Russian group known as APT 28 (Reported [21]). The UK profile says Unit 26165 conducted operations to sabotage TV5 Monde in 2015 and that France attributed this to Unit 26165 in 2025, and the French foreign ministry stated on 29 April 2025 that APT28 was used by the GRU in the sabotage (Confirmed [22][23]). CrowdStrike's June 2016 post says FANCY BEAR "has also been linked publicly" to the Bundestag and TV5 Monde intrusions, a relayed linkage rather than its own finding (Reported [24]). ATT&CK's APT28 entry ([G0007](/mitre/groups/G0007.md)) attributes the group to GRU unit 26165, and its description does not mention either event (Confirmed [34]). The home for both is [Russia-attributed threat actors](/case-studies/THREAT_ACTORS_RUSSIA.md) (Confirmed [135]).

**APT29 and the DNC (summary; home: Fancy Bear Goes Phishing).** JAR-16-20296A of 29 December 2016 says APT29 entered a US political party's systems in summer 2015 after a spearphishing campaign that sent a malicious link to over 1,000 recipients, including multiple US Government victims, then delivered malware, established persistence, escalated privileges, enumerated Active Directory accounts and exfiltrated email over encrypted connections; APT28 entered in spring 2016 (Confirmed [56]). CrowdStrike's incident response found COZY BEAR at the DNC going back to summer 2015 and FANCY BEAR separately from April 2016, with no collaboration seen between the two (Confirmed [24]). ATT&CK's APT29 page ([G0016](/mitre/groups/G0016.md)) attributes the group to Russia's SVR and says it reportedly compromised the DNC starting in summer 2015 (Confirmed [57]). The home is [Fancy Bear Goes Phishing](/case-studies/FANCY_BEAR_GOES_PHISHING_CASES.md) (Confirmed [135]).

**HAMMERTOSS and the Dukes.** FireEye's July 2015 report says HAMMERTOSS, found in early 2015, comes from APT29, "a group that we suspect the Russian government sponsors", and takes commands through daily-generated Twitter handles that point to GitHub-hosted images carrying appended encrypted commands (Confirmed [58]). ATT&CK's HAMMERTOSS entry ([S0037](/mitre/software/S0037.md)), "used by APT29 in 2015", lists seven techniques (Part 9) (Confirmed [59]). F-Secure's September 2015 whitepaper assesses a group "we believe has been working for the Russian Federation since at least 2008" (Confirmed [60]).

**Turla's satellite links.** Kaspersky reported on 9 September that Turla hijacked downstream-only DVB-S satellite internet links, mostly of providers covering the Middle East and Africa, to hide its command and control (Confirmed [83]). ATT&CK attributes Turla ([G0010](/mitre/groups/G0010.md)) to Russia's FSB, with victims in over 50 countries since at least 2004 (Confirmed [84]).

### The Ukrainian blackout (summary; home: Sandworm Operations)

On 23 December remote cyber intrusions at three Ukrainian regional power distribution companies caused outages for about 225,000 customers; six organizations were intruded in all, three without operational impact (Confirmed [78]). The intruders operated breakers remotely through operating-system remote administration tools or ICS client software over VPN, likely with legitimate credentials; KillDisk wiped systems and master boot records at the end; firmware on substation serial-to-Ethernet devices was corrupted; and UPS disconnects were scheduled through remote management (Confirmed [78]). BlackEnergy was found on each company's network, reportedly delivered by spear-phishing with malicious Office attachments, but its role in the outages was unknown (Confirmed [78]). The alert's original text described only external attackers; its 20 July 2021 update says the US Government attributes the activity to Russian nation-state cyber actors (Confirmed [78]). A Western District of Pennsylvania indictment filed on 15 October 2020 alleges that GRU conspirators hacked three Ukrainian energy distribution companies on or about 23 December 2015 and cut power to more than 225,000 customers using BlackEnergy and KillDisk (Confirmed as charged [81]). ATT&CK records the operation as campaign [C0028](/mitre/campaigns/C0028.md), "2015 Ukraine Electric Power Attack", by Sandworm Team ([G0034](/mitre/groups/G0034.md)) with BlackEnergy ([S0089](/mitre/software/S0089.md)) and KillDisk ([S0607](/mitre/software/S0607.md)), first seen December 2015 and last seen January 2016, with an ICS layer; G0034 attributes the group to GRU unit 74455 and records the October 2020 indictment of six of its officers (Confirmed [79][80]). The UK profile puts the loss at 230,000 people without power for one to six hours (Confirmed [22]). The home is [Sandworm Operations](/case-studies/SANDWORM_OPERATIONS.md) (Confirmed [135]).

### China-linked reporting

- **APT30.** FireEye's April 2015 report describes a decade-long espionage operation since at least 2005 against government and commercial targets in Southeast Asia and India, using ASEAN-themed lures, and says its targets "align with Chinese government interests", alignment rather than attribution (Confirmed [85]). ATT&CK describes APT30 ([G0013](/mitre/groups/G0013.md)) as "suspected to be associated with the Chinese government" (Confirmed [86]).
- **Naikon.** Kaspersky's report of 14 May describes at least five years of high-volume geopolitical attacks around the South China Sea since at least 2010, with operators assigned per country (Confirmed [87]). ATT&CK assesses Naikon ([G0019](/mitre/groups/G0019.md)) as state-sponsored and attributed to PLA Unit 78020, citing ThreatConnect and DGI's Project CameraShy of 23 September 2015, whose PDF returned 404 (Reported [88]).
- **Lotus Blossom.** Unit 42's report of 16 June describes a persistent espionage campaign against government and military organizations in Southeast Asia; ATT&CK tracks the actor as [G0030](/mitre/groups/G0030.md) (Confirmed [89]).
- **Threat Group-3390.** ATT&CK describes TG-3390 ([G0027](/mitre/groups/G0027.md)) as a Chinese group that has extensively used strategic web compromises, citing a Dell SecureWorks report of 5 August 2015 that was not opened here (Confirmed for what ATT&CK records [90]).
- **The Great Cannon.** GitHub reported the largest DDoS attack in github.com's history, beginning about 02:00 UTC on 26 March (Confirmed [15]). Citizen Lab reported on 10 April that a tool it calls the Great Cannon, separate from but co-located with the Great Firewall, was first known to be used against GitHub and GreatFire.org servers; the attribution is Citizen Lab's research finding (Confirmed [16]).

### Equation and Duqu 2.0 (summary)

Kaspersky named the Equation group on 16 February: one command server was registered in August 2001 and others possibly as early as 1996, samples were compiled in 2002, a module could reprogram the hard-drive firmware of over a dozen brands, and the implants included EquationLaser, EquationDrug, DoubleFantasy, TripleFantasy, Fanny and GrayFish; no country is named in the text read (Confirmed [8]). ATT&CK's Equation ([G0020](/mitre/groups/G0020.md)) binds the group to no state (Confirmed [9]). The library's homes for Equation are [United States-attributed threat actors](/case-studies/THREAT_ACTORS_UNITED_STATES.md) for the platform and attribution question and [Stuxnet](/case-studies/STUXNET.md) for its link to the Stuxnet developers (Demonstrated [135]).

Kaspersky disclosed Duqu 2.0 on 10 June after detecting an intrusion into its own internal systems; some 2014 to 2015 infections were linked to P5+1 Iran nuclear negotiation venues and to an event for the 70th anniversary of the liberation of Auschwitz-Birkenau, a Windows kernel zero-day was used, and the aim was to spy on Kaspersky's technologies and research; no state is named (Confirmed [38]). A reader-thread comment on the same page by Kaspersky researcher Costin Raiu identifies the zero-day as CVE-2015-2360 (Reported [38]). ATT&CK's Duqu ([S0038](/mitre/software/S0038.md)) cites the June 2015 paper and has no separate Duqu 2.0 entry (Confirmed [39]). [Stuxnet](/case-studies/STUXNET.md) carries the Duqu family, and [Other states' threat actors](/case-studies/THREAT_ACTORS_OTHER_STATES.md) summarizes Duqu 2.0 (Demonstrated [135]).

### North Korea

On 2 January Treasury announced a new Executive Order authorizing sanctions on the North Korean government and the Workers' Party of Korea, citing the cyber attack on Sony Pictures Entertainment, and designated three entities and ten individuals under it (Confirmed [5]). The criminal complaint against Park Jin Hyok, filed in the Central District of California on 8 June 2018, alleges that computers at a Vietnamese bank were compromised in late 2015, that unauthorized SWIFT messages were sent in December 2015, that an account accessed from a North Korean IP address researched the bank's BIC code, and that Park worked for Chosun Expo, a front for the organization "Lab 110" (Confirmed as charged [91]). AA20-239A of 26 August 2020 says the BeagleBoyz, an element of North Korea's RGB, have attempted to steal nearly USD 2 billion since at least 2015 according to public estimates (Confirmed [92]). The home is [North Korea-attributed threat actors](/case-studies/THREAT_ACTORS_NORTH_KOREA.md) (Demonstrated [135]).

### When the names arrived

Read together, the year's state record was named late. OPM's primary record names no actor; the Ukrainian alert named no attacker until a 2021 update and a 2020 indictment; the Bundestag and TV5Monde attributions are official only in the UK profile and France's 2025 statement; and the Equation and Duqu 2.0 disclosures attribute nothing (Inferred [26][78][81][22][23][8][38]). The exceptions were the January sanctions on North Korea and the September commitment with China, which were policy acts rather than attributions of 2015 intrusions (Confirmed [5][66]; Inferred for the reading).

## Part 3: the vulnerability record

### Shared code and protocols

- **GHOST.** Qualys published its advisory on 27 January for CVE-2015-0235, a heap buffer overflow in glibc reachable through the gethostbyname functions; NVD published the record on 28 January with CWE-787, for glibc 2.2 and other 2.x versions before 2.18; it is not in KEV (Confirmed [6][7]).
- **FREAK.** NVD published CVE-2015-0204, OpenSSL's RSA-to-EXPORT_RSA downgrade, on 9 January with CWE-310; Microsoft issued Security Advisory 3046015 for Schannel on 5 March; US-CERT's alert of 6 March said the weakness allowed decryption between vulnerable clients and servers and pointed to VU#243585, and Google updated Android and Chrome for OS X; it is not in KEV (Confirmed [14][13]).
- **Logjam.** The researchers made Logjam public on 20 May and presented the paper at ACM CCS on 13 October; the attack downgrades vulnerable TLS connections to 512-bit export-grade Diffie-Hellman, affected servers supporting DHE_EXPORT and, at disclosure, all modern browsers, and the researchers advised disabling export suites, using 2048-bit groups and upgrading OpenSSH (Confirmed [37]). NVD published CVE-2015-4000 on 21 May with CWE-310, and the CNA lists CWE-295; it is not in KEV (Confirmed [36]). The researchers say 8.4% of the Top 1 Million domains were initially vulnerable, and estimate that a nation-state could break a shared 1024-bit prime and passively decrypt a large share of HTTPS, VPN and SSH servers, adding that NSA leaks are consistent with such a break; both are their estimates (Reported [37]).
- **VENOM.** NVD published CVE-2015-3456, a QEMU floppy disk controller flaw affecting Xen 4.5.x and earlier and KVM guests, on 13 May with CWE-119; it is not in KEV (Confirmed [35]).
- **Java deserialization.** US-CERT's alert of 13 November covered the Apache Commons Collections deserialization flaw (VU#576313) (Confirmed [71]). Oracle's Security Alert for CVE-2015-4852 covers WebLogic Server 10.3.6.0, 12.1.2.0, 12.1.3.0 and 12.2.1.0, remotely exploitable without authentication; NVD published it on 18 November with CWE-502, and KEV added it on 3 November 2021 (Confirmed [72][73]).
- **ProFTPD (summary).** NVD published CVE-2015-3306, ProFTPD mod_copy, on 18 May with CWE-284; KEV added it on 8 October 2026. The home is [ProFTPD mod_copy](/case-studies/PROFTPD_MOD_COPY_CVE_2015_3306.md) (Confirmed [101][135]).

### Microsoft's year

Microsoft published bulletins MS15-001 (13 January) through MS15-135 (8 December); no MS15-136 exists, so 2015 carried 135 bulletins (Confirmed [95]; Inferred for the count).

- **MS15-011 (10 February).** Group Policy remote code execution, rated Critical (Confirmed [96]).
- **MS15-034 (14 April).** HTTP.sys remote code execution, CVE-2015-1635, Critical for Windows 7 through Server 2012 R2; Microsoft had no information of attacks at release and gave disabling IIS kernel caching as a workaround (Confirmed [30]). NVD lists CWE-94, and KEV added it on 10 February 2022 (Confirmed [29]).
- **MS15-051 (12 May).** Windows kernel-mode driver elevation of privilege, including Win32k CVE-2015-1701, which NVD says was exploited in the wild in April 2015 and published on 21 April; KEV added it on 3 March 2022 and flags known ransomware campaign use (Confirmed [32][31][99]). ATT&CK's T1068 page lists APT28 ([G0007](/mitre/groups/G0007.md)) and JHUHUGIT ([S0044](/mitre/software/S0044.md)) as having used CVE-2015-1701 and CVE-2015-2387, and G0007 lists T1134.001 through CVE-2015-1701 (Confirmed [33][34]).
- **MS15-078 (20 July).** Out of band, for the Adobe Type Manager Library OpenType font driver, CVE-2015-2426, Critical on all supported Windows; publicly disclosed but not known to be exploited at release; re-released on 29 July for Windows 10; KEV added it on 28 March 2022 (Confirmed [45]).
- **MS15-093 (18 August).** Out of band for Internet Explorer 7 to 11, CVE-2015-2502 memory corruption, Critical on Windows clients; the bulletin marks it exploited at release; KEV added it on 13 April 2022 (Confirmed [98]).
- **Windows Server 2003 and Windows 10.** Microsoft lists Windows Server 2003's extended support end as 7/15/2015 6:59:59 AM PT, and Windows 10 version 1507 began support on 29 July and version 1511 on 10 November (Confirmed [117][118]).

### Hacking Team and the Flash zero-days (summary; home: The Zero-Day Market)

Wired reported that on the night of Sunday 5 July unidentified hackers published a roughly 400 GB trove of the Milan firm's internal documents, emails, customer invoices and source code (Reported [42]). CERT/CC's VU#561288 for the Flash ByteArray use-after-free CVE-2015-5119 gives 5 July as the date public, was first published on 7 July, states that the bug was discovered by HackingTeam, and records the fix in Flash 18.0.0.203 (Confirmed [44]). NVD published CVE-2015-5119 on 8 July with CWE-416, says it was exploited in the wild in July 2015, and records its KEV addition on 3 March 2022; CVE-2015-5122 (VU#338736), also exploited in the wild in July 2015, was published on 14 July with CWE-416 and added to KEV on 13 April 2022 (Confirmed [43][44]). The home study lists both among the leak's bugs (Confirmed [135]). ATT&CK's Hacking Team UEFI Rootkit ([S0047](/mitre/software/S0047.md)) cites Trend Micro, 13 July 2015, but the record opened does not tie it to the Flash bugs (Confirmed [102]). The home is [The Zero-Day Market](/case-studies/ZERO_DAY_MARKET_EVENTS.md) (Confirmed [135]).

### Mobile: Stagefright

CERT/CC's VU#924951 covers the Android media playback service, made public on 21 July and first published on 28 July: CVE-2015-1538, -1539, -3824, -3826, -3827, -3828, -3829, -3864 (an incomplete original patch) and -6602; Android 2.2 up to but not including 5.1.1_r9; Stagefright 2.0 fixed in builds with the 2015-11-01 security patch level; carriers controlled when updates arrived, and turning off MMS auto-retrieve was a mitigation (Confirmed [52]). US-CERT's alert of 28 July gave Android 2.2 through 5.1.1_r5 (Confirmed [51]). Google's August 2015 Android Security Bulletin, published 13 August under its monthly release process, lists libstagefright MP4 integer overflows including CVE-2015-1538, Critical, credited to Joshua Drake (Confirmed [54]). NVD published CVE-2015-1538 on 1 October with CWE-189, a retired category; it is not in KEV (Confirmed [53]).

### Network devices: Juniper ScreenOS

US-CERT reported on 17 December that Juniper had discovered unauthorized code in ScreenOS that could let an attacker take control of NetScreen devices and decrypt VPN connections (Confirmed [75]). CERT/CC's VU#640184 lists CVE-2015-7755, unauthorized remote administrative access in ScreenOS 6.3.0r17 to 6.3.0r20, and CVE-2015-7756, VPN traffic decryption that cannot be detected, with fixes in Juniper JSA10713 (Confirmed [76]). NVD published both on 19 December: CVE-2015-7755 with CWE-287, added to KEV on 2 October 2025, and CVE-2015-7756 with CWE-310, not in KEV; nothing opened attributes the inserted code to any state (Confirmed [77]).

### The KEV tail

US-CERT's TA15-119A of 29 April listed the top 30 targeted high-risk vulnerabilities in unpatched Adobe, Microsoft, Oracle and OpenSSL software, based on Canadian CCIRC analysis with partners in New Zealand, the UK and Australia (Confirmed [97]). The KEV catalog downloaded on 12 November 2026 holds 48 CVE-2015 entries, dominated by Microsoft and Adobe Flash; those flagged for known ransomware use are CVE-2015-1701, CVE-2015-2291 (an Intel driver), CVE-2015-2546 and CVE-2015-7645 (Flash); late additions include CVE-2015-7755 (2 October 2025), CVE-2015-3246 and CVE-2015-5287 (26 August 2026), and CVE-2015-3306 and BIND CVE-2015-5477 (8 October 2026) (Confirmed [99]). Other 2015 client and server bugs in KEV include Word CVE-2015-1641 (CWE-787, added 3 November 2021), Office EPS CVE-2015-2545 and Java SE CVE-2015-2590 (both 3 March 2022) and Elasticsearch CVE-2015-1427 (25 March 2022), while Joomla CVE-2015-8562, exploited in the wild in December 2015 (CWE-20), is not in KEV (Confirmed [100]). KEV dates are catalog dates, not exploitation dates (Confirmed [99]).

## Part 4: below the operating system and into the supply chain

- **Disk firmware.** Equation's module could reprogram the hard-drive firmware of over a dozen brands, and ATT&CK lists T1542.002, Component Firmware, for the group (Confirmed [8][9]).
- **System firmware.** ATT&CK's Hacking Team UEFI Rootkit lists T1542.001, System Firmware, and T1014, Rootkit, citing Trend Micro, 13 July 2015 (Confirmed [102]).
- **Router boot images.** US-CERT reported on 12 August that Cisco had observed increasingly complex attacks that install a malicious ROMMON image on Cisco IOS devices to gain administrative access (Confirmed [62]).
- **Router implants.** Mandiant reported SYNful Knock on 15 September, with at least 14 implants found across Ukraine, the Philippines, Mexico and India; ATT&CK's [S0519](/mitre/software/S0519.md) lists T1556.004, T1601.001 and T1205, citing that report and Cisco's of 8 October 2015 (Confirmed [63][64]).
- **Firewall code.** Juniper's ScreenOS contained unauthorized code (Part 3); how it entered was not established in any record opened here (Confirmed [75]).
- **Developer tools.** Unit 42 reported on 17 September that trojanized Xcode installers uploaded to Baidu's file-sharing service infected iOS apps built by Chinese developers, that at least two infected apps passed Apple's review and reached the App Store, that the malware collected device information for its command servers, and that Baidu removed the files after notification (Confirmed [65]).
- **Preinstalled software.** US-CERT's TA15-051A of 20 February said Superfish VisualDiscovery, which Lenovo shipped on consumer PCs from September 2014, installs a non-unique trusted root CA certificate that lets an attacker spoof HTTPS (Confirmed [12]).

## Part 5: crime, breaches and the courts

### Banking crime

**Carbanak.** Kaspersky announced Carbanak with INTERPOL and Europol on 17 February: a gang active since 2013 attempted attacks on up to 100 banks and other financial institutions in about 30 countries, gained access by spear phishing an employee, moved laterally and watched administrators, and took money through online banking or e-payment transfers, inflated account balances and ATMs ordered to dispense cash at preset times (Confirmed [10]). Its figure of up to USD 1 billion stolen in about two years is the vendor's estimate, not a court finding (Reported [10]). ATT&CK's [G0008](/mitre/groups/G0008.md) describes a cybercriminal group targeting financial institutions since at least 2013, citing Kaspersky GReAT (February 2015) and Fox-IT (16 February 2015), and its malware is [S0030](/mitre/software/S0030.md) (Confirmed [11][131]).

**Dridex.** US-CERT's TA15-286A of 13 October, released by DHS with the FBI and DOJ, describes Dridex as a peer-to-peer bank-credential-stealing trojan spread by phishing email with obfuscated macros in Office and XML files, stealing credentials through keystroke logging and web injects, with infected hosts able to send spam and join DDoS (Confirmed [67]). ATT&CK's Dridex is [S0384](/mitre/software/S0384.md), and the library ties it to Indrik Spider ([G0119](/mitre/groups/G0119.md)) (Confirmed [131]). The DOJ charging release was not opened.

**The newswire scheme.** The SEC charged 32 defendants on 11 August in a scheme that used stolen nonpublic earnings releases: two Ukrainian men allegedly hacked newswire services, and traders allegedly made more than USD 100 million; the complaint was filed under seal on 10 August in Newark (Confirmed as charged [61]).

**A Vietnamese bank.** See Part 2: the Park complaint alleges unauthorized SWIFT messages in December 2015 (Confirmed as charged [91]).

### Ransomware, botnets and DDoS extortion

- **CryptoWall.** US-CERT relayed an IC3 alert on 23 June that US individuals and businesses remained at risk from CryptoWall, and discouraged paying the ransom (Confirmed [40]).
- **Simda.** TA15-105A of 15 April, released by DHS with Interpol and the FBI as part of the takedown, said the Simda botnet had compromised more than 770,000 computers worldwide (Confirmed [25]).
- **Dorkbot.** TA15-337A of 3 December, citing Microsoft, said Dorkbot infected more than one million PCs in over 190 countries over the past year, and that DHS, the FBI and Microsoft acted together to disrupt it (Confirmed [74]).
- **DDoS extortion.** US-CERT relayed an IC3 alert on 31 July about a rise in DDoS extortion e-mail campaigns against US businesses (Confirmed [55]).
- **Web shells.** TA15-314A of 10 November, with UK, Australian, Canadian and New Zealand partners, warned of compromised web servers and web shells used by APT and criminal groups (Confirmed [70]).

### The IC3 count

IC3's 2015 report counts 288,012 complaints and USD 1,070,711,522 in reported losses; business email compromise accounted for 7,838 complaints and over USD 263 million, with email account compromise, tracked from 2015, adding 281 complaints and over USD 11 million (over 8,000 BEC and EAC complaints with nearly USD 275 million combined); ransomware accounted for 2,453 complaints and over USD 1.6 million; and the year's public service announcements included CryptoWall and BEC (Confirmed [82]; Inferred for the reconciliation of the two BEC figures). These are complaint figures, not total crime (Confirmed [82]).

### Markets and forums in court

- **Silk Road.** A jury convicted Ross Ulbricht (Dread Pirate Roberts) on all seven counts after a trial from 13 January to 4 February; on 29 May he was sentenced to life imprisonment; the Second Circuit affirmed on 31 May 2017, and its opinion records sentences of 78 months for DEA agent Force and 71 months for Secret Service agent Bridges, without dates (Confirmed [93]).
- **Darkode.** On 15 July the FBI and DOJ announced Operation Shrouded Horizon: law enforcement in 20 countries, charges, arrests and searches involving 70 members and associates, US indictments against 12 people including the administrator, and seizure of the forum's domain and servers (Confirmed [94]).

### Data breaches

- **Ashley Madison.** The joint report of the Privacy Commissioner of Canada and the Australian Information Commissioner (22 August 2016) records unusual database activity on 12 July, the attacker's notice on 13 July and the Impact Team's announcement on 15 July; Avid Life Media reported to the Canadian commissioner on 20 July and issued press releases on 20 July and 18 August; files covering about 36 million user accounts were published on 18 and 20 August; entry was likely through a compromised employee's valid credentials and a single-factor VPN, and the attacker deleted logs; the commissioners found contraventions of PIPEDA and the Australian Privacy Act (Confirmed [46]). Wired reported that the Impact Team had demanded that AshleyMadison.com and Established Men be taken down (Reported [47]).
- **TalkTalk.** The ICO's account says SQL injection against three legacy Tiscali webpages ran from 15 to 21 October, the sites were taken down on 21 October and the ICO was notified on 22 October; personal data of 156,959 customers were accessed, with bank account number and sort code for 15,656; two earlier SQL injection attacks, on 17 July and 2 to 3 September, went unacted; the database software lacked a fix that had been available for over three and a half years; and the GBP 400,000 fine, the ICO's largest at the time, was settled on 1 November 2016 (Confirmed [69]). The BBC reported the fine on 5 October 2016 (Reported [68]).
- **IRS Get Transcript.** On 26 May the IRS said it had temporarily shut down the application the week before, after about 100,000 taxpayer accounts were accessed out of about 200,000 attempts made from February to mid-May, and that it would mail letters to the taxpayers involved and offer credit monitoring to those whose accounts were accessed (Confirmed [110]).
- **VTech.** VTech learned from a journalist in November 2015 that its network had been accessed; Learning Lodge then held about 2.25 million parent accounts for nearly 3 million children and Kid Connect about 638,000 child accounts; the FTC settled on 8 January 2018 for USD 650,000 over COPPA violations and data its privacy policy said were encrypted but were not (Reported [111]; the FTC release could not be reopened on 2026-11-13, so this study does not grade it Confirmed).
- **Anthem, OPM and Hacking Team.** See Parts 2 and 3.

## Part 6: vehicles and phones

Wired reported on 21 July that researchers remotely controlled a Jeep, and its 24 July update says Chrysler recalled 1.4 million vehicles as a result (Reported [49]). NHTSA's recall 15V-461, received on 23 July, covers 1,416,903 FCA US vehicles, including 2014 to 2015 Jeep Grand Cherokee and Cherokee, 2013 to 2015 Ram and 2015 Chrysler 200 and 300, whose radio software vulnerabilities let third parties reach networked vehicle control systems; the carrier closed the open cellular connection, the remedy is a USB software update, and the recall began on 25 August (Confirmed [50]). US-CERT's alert of 27 July says Sprint blocked the port used for attacks and FCA and NHTSA started a safety recall (ICS Alert 15-203-01, VU#819439) (Confirmed [48]). Stagefright (Part 3) made a phone's media engine reachable by a message, and carriers controlled when fixes arrived (Confirmed [52]). The library's [automotive security reference](/AUTOMOTIVE_SECURITY_REFERENCE.md) and [mobile security reference](/MOBILE_SECURITY_REFERENCE.md) cover the defender side.

## Part 7: law, policy and standards

### United States

- **Sanctions.** The President's 2 January order on North Korea, under which Treasury designated three entities and ten individuals that day; Executive Order 13694 of 1 April, published on 2 April at 80 FR 18077, declares a national emergency and authorizes blocking the property of persons responsible for significant malicious cyber-enabled activities, including harming critical-infrastructure networks, causing major outages and stealing funds, trade secrets or personal data for commercial advantage (Confirmed [5][17][18]).
- **Information sharing.** Executive Order 13691 of 13 February, published on 20 February at 80 FR 9349, directs DHS to encourage Information Sharing and Analysis Organizations and select an ISAO Standards Organization, and lets the NCCIC enter voluntary agreements with ISAOs (Confirmed [19][20]). Public Law 114-113, the Consolidated Appropriations Act, 2016, enacted on 18 December, carries in Division N the Cybersecurity Act of 2015: Title I is the Cybersecurity Information Sharing Act of 2015 (authorizations to prevent, detect, analyze and mitigate threats in section 104, sharing of cyber threat indicators and defensive measures with the federal government in section 105, liability protection in section 106 and an effective period in section 111), Title II subtitle B is Federal Cybersecurity Enhancement, Title III a federal cybersecurity workforce assessment, and Title IV section 405 cybersecurity in the health care industry (Confirmed [105]). CISA says it is the federal hub for indicator sharing under the act, that DHS certified Automated Indicator Sharing in March 2016, and, in a February 2026 update, that the act's effective period was extended through 30 September 2026 (Confirmed [106]).
- **The federal response to OPM.** OMB's M-16-04 of 30 October records that the Federal CIO launched a 30-day Cybersecurity Sprint on 12 June (strong authentication, patching, indicator scanning, high-value assets, fewer privileged accounts), that civilian strong-authentication use rose from 42 to 72 percent and for privileged users from 33 to nearly 75 percent, and that DHS was to accelerate CDM and EINSTEIN (Confirmed [113]).
- **Export controls.** On 20 May BIS proposed a rule to implement the Wassenaar Arrangement's 2013 controls on intrusion software and IP network communications surveillance items (doc 2015-11642, 80 FR 28853) (Confirmed [104]).
- **Regulators and courts.** The Third Circuit's opinion in FTC v. Wyndham (24 August) affirmed that the FTC can act on deficient cybersecurity under the unfairness prong of section 45(a) and that Wyndham had fair notice, after three breaches in 2008 and 2009, more than 619,000 consumers' card data taken and at least USD 10.6 million in fraud loss; the home is [E-Commerce Threats](/case-studies/ECOMMERCE_THREATS.md) (Confirmed [108][135]). On 22 September the SEC censured R.T. Jones Capital Equities Management and imposed a USD 75,000 penalty for having no written cybersecurity policies under Regulation S-P Rule 30(a) (Confirmed [112]).
- **NIST.** SP 800-161 on supply chain risk management (8 April), SP 800-82 Rev. 2 on industrial control system security (May; final listed 3 June) and SP 800-171 on controlled unclassified information in nonfederal systems (18 June) (Confirmed [114][115][116]).

### International

- **US-China.** The fact sheet of 25 September on President Xi's state visit records that neither government will conduct or knowingly support cyber-enabled theft of intellectual property for commercial advantage, creates a senior experts group on norms, sets up a ministerial-level joint dialogue on cybercrime co-chaired by the DHS Secretary and the Attorney General with a hotline and a first meeting by the end of 2015, and welcomes the July 2015 UN GGE report; the home is [The Hacker and the State](/case-studies/HACKER_AND_THE_STATE_CASES.md) (Confirmed [66][135]).
- **UN norms.** The GGE report A/70/174 of 22 July recommends that a state not conduct or knowingly support ICT activity that intentionally damages critical infrastructure, not harm other states' authorized emergency response teams, and encourage responsible reporting of ICT vulnerabilities (Confirmed [109]).
- **Europe.** On 6 October the CJEU ruled in Case C-362/14, Schrems v Data Protection Commissioner, that the Commission's US Safe Harbour decision is invalid (Confirmed [107]).

### Standards, catalogs and products

- **TLS.** RFC 7465 (February) prohibits RC4 cipher suites in any TLS version; RFC 7525, BCP 195 (May), says implementations must not negotiate SSLv2, SSLv3 or RC4, must support TLS 1.2 and must support and prefer forward-secret suites; RFC 7568 (June) says SSLv3 must not be used (Confirmed [121][122][123]).
- **Certificates.** Let's Encrypt issued its first certificate on 14 September, applied to the Mozilla, Google, Microsoft and Apple root programs, and entered public beta on 3 December after issuing over 26,000 certificates in the limited beta (Confirmed [124][125]).
- **MITRE catalogs.** ATT&CK went public in May with 96 techniques; CAPEC 2.7 (10 November) added a Mobile view and 51 patterns and CAPEC 2.8 (7 December) added three; CWE 2.9 (7 December), the only CWE release of 2015, added the CWE-1003 view, and 42 products were recognized CWE-Compatible by December (Confirmed [126][130][129]).
- **Windows.** PowerShell v5 and KB 3000850 added script block logging (event 4104) and enhanced transcription, AMSI arrived on Windows 10, and Constrained Language Mode applies under AppLocker allow-mode policies (Confirmed [119]). Microsoft LAPS gives each domain-joined computer a unique random local administrator password stored in a confidential AD attribute; the page opened shows only its 2024 re-release (Confirmed [120]).

## Part 8: the defender view

**Remote access with valid credentials was the door that mattered.** The Ukrainian operators came in over VPN with likely legitimate credentials, Ashley Madison's attacker through a single-factor VPN with an employee's credentials, and OPM's adversary with a contractor's credentials (Confirmed [78][46][26]). The library links [Session Termination](/mitre/d3fend/session-termination.md) to T1133 and [Change Default Password](/mitre/d3fend/change-default-password.md), [Access Modeling](/mitre/d3fend/access-modeling.md), [Account Locking](/mitre/d3fend/account-locking.md) and [User Account Permissions](/mitre/d3fend/user-account-permissions.md) to T1078 (Demonstrated [133]); [Multi-factor Authentication](/mitre/d3fend/multi-factor-authentication.md) is a name-fit pairing only (Inferred [133]). [M1032 Multi-factor Authentication](/mitre/mitigations/M1032.md), [M1030 Network Segmentation](/mitre/mitigations/M1030.md) and [M1035 Limit Access to Resource Over Network](/mitre/mitigations/M1035.md) are the ATT&CK mitigations (Inferred).

**Destruction followed intrusion.** KillDisk wiped files and boot records in Ukraine, and the ICS alert's mitigations were application whitelisting, network isolation, controlled remote access with MFA and contingency planning (Confirmed [78]). The library links [Disk Partitioning](/mitre/d3fend/disk-partitioning.md) to T1561.002 and nothing to T1485 (Demonstrated [133]); [Executable Allowlisting](/mitre/d3fend/executable-allowlisting.md) is a name-fit pairing for the alert's whitelisting advice (Inferred), and [M1053 Data Backup](/mitre/mitigations/M1053.md) and [M1038 Execution Prevention](/mitre/mitigations/M1038.md) are the ATT&CK mitigations (Inferred).

**Firmware and device images needed verification.** Disk firmware, UEFI, ROMMON and router images were all reported as implant locations (Confirmed [8][102][62][63]). The library links [Firmware Verification](/mitre/d3fend/firmware-verification.md), [System Firmware Verification](/mitre/d3fend/system-firmware-verification.md), [Firmware Behavior Analysis](/mitre/d3fend/firmware-behavior-analysis.md) and [Firmware Embedded Monitoring Code](/mitre/d3fend/firmware-embedded-monitoring-code.md) to T1542.001 and T1542.004, and all but System Firmware Verification to T1542.002 (Demonstrated [133]). It maps nothing to T1556.004 or T1601.001, so SYNful Knock's router-image tampering cannot be bound to a countermeasure through the library's data (Demonstrated [133]). [M1046 Boot Integrity](/mitre/mitigations/M1046.md) and [M1045 Code Signing](/mitre/mitigations/M1045.md) are the ATT&CK mitigations (Inferred).

**Vendor code and developer tools were attack paths.** ScreenOS carried unauthorized code and XcodeGhost rode a trojanized Xcode (Confirmed [75][65]). The library links [Software Inventory](/mitre/d3fend/software-inventory.md), [Software Update](/mitre/d3fend/software-update.md), [Restore Software](/mitre/d3fend/restore-software.md) and [Asset Vulnerability Enumeration](/mitre/d3fend/asset-vulnerability-enumeration.md) to T1195.001 and T1195.002 (Demonstrated [133]); the pairing with ScreenOS is tentative because its entry path is not established (Inferred).

**Internet-facing middleware and web applications were exploited.** WebLogic, Joomla and TalkTalk's legacy pages were reached from the internet, and TA15-314A warned of web shells (Confirmed [72][100][69][70]). The library links [Inbound Traffic Filtering](/mitre/d3fend/inbound-traffic-filtering.md), [Network Traffic Signature Analysis](/mitre/d3fend/network-traffic-signature-analysis.md), [Database Query String Analysis](/mitre/d3fend/database-query-string-analysis.md) and [Client-server Payload Profiling](/mitre/d3fend/client-server-payload-profiling.md) to T1190, and [Executable Allowlisting](/mitre/d3fend/executable-allowlisting.md), [File Integrity Monitoring](/mitre/d3fend/file-integrity-monitoring.md) and [Process Spawn Analysis](/mitre/d3fend/process-spawn-analysis.md) to T1505.003 (Demonstrated [133]); [M1051 Update Software](/mitre/mitigations/M1051.md) and [M1016 Vulnerability Scanning](/mitre/mitigations/M1016.md) are the ATT&CK mitigations (Inferred).

**Client exploits needed exploit protection while fixes shipped.** Flash, Internet Explorer and Win32k bugs were exploited at or before release (Confirmed [43][98][31]). The library links [Process Segment Execution Prevention](/mitre/d3fend/process-segment-execution-prevention.md), [Segment Address Offset Randomization](/mitre/d3fend/segment-address-offset-randomization.md), [Stack Frame Canary Validation](/mitre/d3fend/stack-frame-canary-validation.md), [Shadow Stack Comparisons](/mitre/d3fend/shadow-stack-comparisons.md), [Memory Boundary Tracking](/mitre/d3fend/memory-boundary-tracking.md) and [Process Code Segment Verification](/mitre/d3fend/process-code-segment-verification.md) to T1203 and T1068 (Demonstrated [133]); [M1050 Exploit Protection](/mitre/mitigations/M1050.md) and [M1021 Restrict Web-Based Content](/mitre/mitigations/M1021.md) are the ATT&CK mitigations (Inferred).

**Phishing opened the banks and the party, and reached the grid.** Carbanak, Dridex and APT29 began with email, and BlackEnergy, whose role in the outages is unknown, was reportedly delivered by spear-phishing (Confirmed [10][78][67][56]). The library links [Email Filtering](/mitre/d3fend/email-filtering.md), [Content Filtering](/mitre/d3fend/content-filtering.md), [File Analysis](/mitre/d3fend/file-analysis.md), [Dynamic Analysis](/mitre/d3fend/dynamic-analysis.md) and [Sender Reputation Analysis](/mitre/d3fend/sender-reputation-analysis.md) to T1566.001 and T1566.002, and [URL Analysis](/mitre/d3fend/url-analysis.md) to T1566.002 (Demonstrated [133]); [M1017 User Training](/mitre/mitigations/M1017.md) and [M1049 Antivirus/Antimalware](/mitre/mitigations/M1049.md) are the ATT&CK mitigations (Inferred).

**Export-grade cryptography had to go.** FREAK and Logjam abused export suites, and the IETF's 2015 RFCs retired RC4 and SSLv3 (Confirmed [13][37][121][122][123]). The library links [Network Traffic Signature Analysis](/mitre/d3fend/network-traffic-signature-analysis.md), [Network Traffic Filtering](/mitre/d3fend/network-traffic-filtering.md) and [Protocol Metadata Anomaly Detection](/mitre/d3fend/protocol-metadata-anomaly-detection.md) to T1557 and nothing to T1600 (Demonstrated [133]); [Message Encryption](/mitre/d3fend/message-encryption.md) is a name-fit pairing only (Inferred), and [M1041 Encrypt Sensitive Information](/mitre/mitigations/M1041.md) and [M1042 Disable or Remove Feature or Program](/mitre/mitigations/M1042.md) are the ATT&CK mitigations (Inferred).

**Identity and script logging arrived as tools.** LAPS addressed shared local administrator passwords, the risk ATT&CK describes as [T1550.002 Pass the Hash](/mitre/techniques/T1550-002.md), and PowerShell v5 logging addressed [T1059.001 PowerShell](/mitre/techniques/T1059-001.md) (Confirmed [120][119]; Inferred for the pairing). The library's D3FEND data maps nothing to T1550.002 or T1059.001; [Credential Rotation](/mitre/d3fend/credential-rotation.md) and [Credential Hardening](/mitre/d3fend/credential-hardening.md) are name-fit pairings only (Demonstrated [133]; Inferred), and [M1026 Privileged Account Management](/mitre/mitigations/M1026.md) and [M1047 Audit](/mitre/mitigations/M1047.md) are the ATT&CK mitigations (Inferred).

**Encrypting malware and DDoS were money problems.** CryptoWall's ransom advice and the DDoS extortion alert arrived the same summer (Confirmed [40][55]). The library links [Restore File](/mitre/d3fend/restore-file.md), [File Integrity Monitoring](/mitre/d3fend/file-integrity-monitoring.md) and [Decoy File](/mitre/d3fend/decoy-file.md) to T1486, and nothing to T1498 (Demonstrated [133]); [M1053 Data Backup](/mitre/mitigations/M1053.md) and [M1037 Filter Network Traffic](/mitre/mitigations/M1037.md) are the ATT&CK mitigations (Inferred).

## Part 9: MITRE mappings

ATT&CK was released publicly in May 2015, but no 2015 event was mapped to it at the time; every binding below is a later mapping (Confirmed [126]; Inferred for the binding). Every id was checked against the library's data files (`data/attack/technique_profiles.jsonl`, `groups.jsonl`, `software.jsonl`, `group_to_technique.jsonl`, `software_to_technique.jsonl`, `campaigns.jsonl`, `campaign_profiles.jsonl`, `superseded_by.jsonl`, `technique_to_d3fend.jsonl`, `d3fend_countermeasures.jsonl`, `data/attack/ics/` and `data/weaknesses/`) and against the generated pages under `mitre/` on 12 and 13 November 2026, and the campaign, group, software and technique pages named were opened on the live ATT&CK site (Demonstrated [131][132][133][134]; Confirmed [79][80][33][103]). Names and tactics are those of ATT&CK v20.0 as the library carries them, including the v20.0 tactics stealth and defense-impairment (Demonstrated [131]).

The Basis column says how strong each tie is, as in the [2016 chronicle](/case-studies/CHRONICLE_2016.md). **Listed** means ATT&CK itself lists the id for an object it ties to a 2015 report or event, or prints a 2015 example on the technique page. **Described** means a primary source describes the behavior and this study assigns the id. **Inferred** means the mapping rests on this study's reading. Caveats on the Listed rows: the citations behind Dridex's (S0384), KillDisk's (S0607), Carbanak's (S0030) and APT29's (G0016) entries were not traced to 2015 records [131]; TG-3390's T1189 rests on a Secureworks report that was not opened [90]; and the T1203 procedure rows name 2015 CVEs without dating their use [103].

### ATT&CK Enterprise techniques

| Id | Name (ATT&CK v20.0) | Tactic(s) | Basis | Dated event or report | Sources |
|---|---|---|---|---|---|
| [`T1566.001`](/mitre/techniques/T1566-001.md) | Spearphishing Attachment | initial-access | Listed (C0028); Described | BlackEnergy's malicious Office attachments (Ukraine, Dec); Carbanak's spear phishing (17 Feb); Dridex macro documents (TA15-286A, 13 Oct) | [79][78][10][67] |
| [`T1566.002`](/mitre/techniques/T1566-002.md) | Spearphishing Link | initial-access | Listed (G0016); Described | APT29's malicious link to over 1,000 recipients (summer) | [57][56] |
| [`T1133`](/mitre/techniques/T1133.md) | External Remote Services | persistence, initial-access | Listed (C0028); Described | Ukrainian operators over VPN (23 Dec); Ashley Madison's single-factor VPN (Jul) | [79][78][46] |
| [`T1078`](/mitre/techniques/T1078.md) | Valid Accounts | stealth, persistence, privilege-escalation, initial-access | Listed (C0028); Described | Likely legitimate credentials in Ukraine (23 Dec); Ashley Madison employee credentials (Jul); OPM contractor credentials (2014 foothold) | [79][78][46][26] |
| [`T1189`](/mitre/techniques/T1189.md) | Drive-by Compromise | initial-access | Listed (G0027) | TG-3390's strategic web compromises (Secureworks, 5 Aug) | [90][131] |
| [`T1190`](/mitre/techniques/T1190.md) | Exploit Public-Facing Application | initial-access | Described | TalkTalk SQL injection (15 to 21 Oct); WebLogic CVE-2015-4852 (Nov); Joomla CVE-2015-8562 exploited (Dec) | [69][72][100] |
| [`T1195.001`](/mitre/techniques/T1195-001.md) | Compromise Software Dependencies and Development Tools | initial-access | Described | XcodeGhost (17 Sep) | [65] |
| [`T1195.002`](/mitre/techniques/T1195-002.md) | Compromise Software Supply Chain | initial-access | Inferred (tentative) | Unauthorized code in ScreenOS (17 Dec); entry path not established | [75][76] |
| [`T1203`](/mitre/techniques/T1203.md) | Exploitation for Client Execution | execution | Listed (technique page rows for G0096, G0040, G0142 with CVE-2015-1641, G0012 with CVE-2015-8651, G0098 with CVE-2015-5119, G0022 with CVE-2015-3113) | Flash zero-days exploited in the wild (Jul); Office and Java bugs later in KEV | [103][43][100] |
| [`T1204.002`](/mitre/techniques/T1204-002.md) | Malicious File | execution | Listed (C0028, S0384) | BlackEnergy attachments (Dec); Dridex documents (13 Oct) | [79][131][67] |
| [`T1059.005`](/mitre/techniques/T1059-005.md) | Visual Basic | execution | Listed (C0028) | Ukraine (Dec) | [79] |
| [`T1059.001`](/mitre/techniques/T1059-001.md) | PowerShell | execution | Listed (S0037) | HAMMERTOSS (Jul) | [59][58] |
| [`T1136.002`](/mitre/techniques/T1136-002.md) | Domain Account | persistence | Listed (C0028) | Ukraine (Dec) | [79] |
| [`T1505.003`](/mitre/techniques/T1505-003.md) | Web Shell | persistence | Described | TA15-314A (10 Nov) | [70] |
| [`T1542.001`](/mitre/techniques/T1542-001.md) | System Firmware | stealth, persistence | Listed (S0047) | Hacking Team UEFI rootkit (Trend Micro, 13 Jul) | [102] |
| [`T1542.002`](/mitre/techniques/T1542-002.md) | Component Firmware | stealth, persistence | Listed (G0020) | Equation's hard-drive firmware module (16 Feb) | [9][8] |
| [`T1542.004`](/mitre/techniques/T1542-004.md) | ROMMONkit | stealth, persistence | Described | Malicious ROMMON images on Cisco IOS (12 Aug) | [62] |
| [`T1556.004`](/mitre/techniques/T1556-004.md) | Network Device Authentication | defense-impairment, persistence, credential-access | Listed (S0519) | SYNful Knock (15 Sep) | [64][63] |
| [`T1601.001`](/mitre/techniques/T1601-001.md) | Patch System Image | defense-impairment | Listed (S0519) | SYNful Knock (15 Sep) | [64][63] |
| [`T1205`](/mitre/techniques/T1205.md) | Traffic Signaling | stealth, persistence, command-and-control | Listed (S0519) | SYNful Knock (15 Sep) | [64] |
| [`T1068`](/mitre/techniques/T1068.md) | Exploitation for Privilege Escalation | privilege-escalation | Listed (technique page rows for G0007 and S0044) | CVE-2015-1701 and CVE-2015-2387 (Win32k exploited Apr) | [33][31] |
| [`T1134`](/mitre/techniques/T1134.md) | Access Token Manipulation | stealth, privilege-escalation | Listed (S0038) | Duqu 2.0 (10 Jun) | [39][38] |
| [`T1134.001`](/mitre/techniques/T1134-001.md) | Token Impersonation/Theft | stealth, privilege-escalation | Listed (G0007) | CVE-2015-1701 | [34] |
| [`T1055`](/mitre/techniques/T1055.md) | Process Injection | stealth, privilege-escalation | Listed (C0028) | Ukraine (Dec) | [79] |
| [`T1014`](/mitre/techniques/T1014.md) | Rootkit | stealth | Listed (S0047) | Hacking Team UEFI rootkit (13 Jul) | [102] |
| [`T1070`](/mitre/techniques/T1070.md) | Indicator Removal | stealth | Described | Ashley Madison attacker deleted logs (Jul) | [46] |
| [`T1070.004`](/mitre/techniques/T1070-004.md) | File Deletion | stealth | Listed (C0028) | Ukraine (Dec) | [79] |
| [`T1218.011`](/mitre/techniques/T1218-011.md) | Rundll32 | stealth | Listed (C0028) | Ukraine (Dec) | [79] |
| [`T1218.007`](/mitre/techniques/T1218-007.md) | Msiexec | stealth | Listed (S0038) | Duqu 2.0 (10 Jun) | [39][38] |
| [`T1564.003`](/mitre/techniques/T1564-003.md) | Hidden Window | stealth | Listed (S0037) | HAMMERTOSS (Jul) | [59] |
| [`T1564.005`](/mitre/techniques/T1564-005.md) | Hidden File System | stealth | Listed (G0020) | Equation (16 Feb) | [9][8] |
| [`T1480.001`](/mitre/techniques/T1480-001.md) | Environmental Keying | stealth | Listed (G0020) | Equation (16 Feb) | [9] |
| [`T1685`](/mitre/techniques/T1685.md) | Disable or Modify Tools | defense-impairment | Listed (C0028) | Ukraine (Dec) | [79] |
| [`T1112`](/mitre/techniques/T1112.md) | Modify Registry | defense-impairment, persistence | Listed (C0028) | Ukraine (Dec) | [79] |
| [`T1600`](/mitre/techniques/T1600.md) | Weaken Encryption | defense-impairment | Inferred | FREAK (Mar) and Logjam (20 May) downgrades; ScreenOS VPN decryption CVE-2015-7756 (17 Dec) | [13][37][76] |
| [`T1557`](/mitre/techniques/T1557.md) | Adversary-in-the-Middle | credential-access, collection | Inferred | FREAK and Logjam require a man-in-the-middle position | [13][37] |
| [`T1056.001`](/mitre/techniques/T1056-001.md) | Keylogging | collection, credential-access | Listed (C0028, S0030); Described | Ukraine (Dec); Carbanak; Dridex keystroke logging (13 Oct) | [79][131][67] |
| [`T1040`](/mitre/techniques/T1040.md) | Network Sniffing | credential-access, discovery | Listed (C0028) | Ukraine (Dec) | [79] |
| [`T1018`](/mitre/techniques/T1018.md) | Remote System Discovery | discovery | Listed (C0028) | Ukraine (Dec) | [79] |
| [`T1087.002`](/mitre/techniques/T1087-002.md) | Domain Account | discovery | Described | APT29 enumerated Active Directory accounts (summer) | [56] |
| [`T1120`](/mitre/techniques/T1120.md) | Peripheral Device Discovery | discovery | Listed (G0020) | Equation (16 Feb) | [9] |
| [`T1570`](/mitre/techniques/T1570.md) | Lateral Tool Transfer | lateral-movement | Listed (C0028) | Ukraine (Dec) | [79] |
| [`T1021.001`](/mitre/techniques/T1021-001.md) | Remote Desktop Protocol | lateral-movement | Listed (S0030); Described | Carbanak; OPM's RDP session (June 2014, recorded in the 2016 timeline) | [131][26] |
| [`T1113`](/mitre/techniques/T1113.md) | Screen Capture | collection | Listed (S0030) | Carbanak watched administrators (17 Feb) | [131][10] |
| [`T1185`](/mitre/techniques/T1185.md) | Browser Session Hijacking | collection | Listed (S0384); Described | Dridex web injects (13 Oct) | [131][67] |
| [`T1071.001`](/mitre/techniques/T1071-001.md) | Web Protocols | command-and-control | Listed (C0028, S0037, S0030, S0384) | Ukraine (Dec); HAMMERTOSS (Jul) | [79][59] |
| [`T1105`](/mitre/techniques/T1105.md) | Ingress Tool Transfer | command-and-control | Listed (C0028) | Ukraine (Dec) | [79] |
| [`T1102.003`](/mitre/techniques/T1102-003.md) | One-Way Communication | command-and-control | Listed (S0037) | HAMMERTOSS's Twitter handles (Jul) | [59][58] |
| [`T1001.002`](/mitre/techniques/T1001-002.md) | Steganography | command-and-control | Listed (S0037) | HAMMERTOSS's image-borne commands (Jul) | [59][58] |
| [`T1573.001`](/mitre/techniques/T1573-001.md) | Symmetric Cryptography | command-and-control | Listed (S0037) | HAMMERTOSS (Jul) | [59] |
| [`T1219`](/mitre/techniques/T1219.md) | Remote Access Tools | command-and-control | Listed (S0030, S0384) | Carbanak (17 Feb); Dridex | [131][10] |
| [`T1567.002`](/mitre/techniques/T1567-002.md) | Exfiltration to Cloud Storage | exfiltration | Listed (S0037) | HAMMERTOSS (Jul) | [59] |
| [`T1485`](/mitre/techniques/T1485.md) | Data Destruction | impact | Listed (S0607); Described | KillDisk wiped files in Ukraine (23 Dec) | [131][78] |
| [`T1561.002`](/mitre/techniques/T1561-002.md) | Disk Structure Wipe | impact | Listed (S0607); Described | KillDisk wiped master boot records (23 Dec) | [131][78] |
| [`T1486`](/mitre/techniques/T1486.md) | Data Encrypted for Impact | impact | Described | CryptoWall (IC3, 23 Jun) | [40] |
| [`T1498`](/mitre/techniques/T1498.md) | Network Denial of Service | impact | Described | GitHub DDoS (26 Mar); DDoS extortion (31 Jul) | [15][16][55] |
| [`T1657`](/mitre/techniques/T1657.md) | Financial Theft | impact | Described | Carbanak's fraudulent transfers and ATM cash-out (17 Feb) | [10] |

Left out on purpose: Anthem, the Bundestag, TV5Monde, OPM's exfiltration, VTech and the Hacking Team breach, whose primaries opened here describe no intrusion technique beyond the rows above [1][3][22][21][26][111][42]; IRS Get Transcript, where taxpayer data from non-IRS sources was used to pass knowledge-based authentication, which this study does not bind to an Enterprise technique [110]; Satellite Turla's hijacked satellite links, Naikon, APT30 and Lotus Blossom, whose technique entries were not traced to their 2015 reports [83][131]; Duqu 2.0's kernel zero-day, whose CVE rests on a reader comment [38]; Superfish, which was preinstalled software rather than an adversary's act [12]; VENOM, GHOST, HTTP.sys and Stagefright, for which no exploitation in 2015 is recorded in the sources opened [35][7][30][53]; Stagefright as an ATT&CK for Mobile matter not bound here [52]; and T1550.002 and T1059.001 as the threats LAPS and PowerShell logging address, which are named in Part 8 as defender context and are not 2015 events (T1059.001 is bound above only through HAMMERTOSS) [120][119].

### ATT&CK for ICS

The live C0028 page lists 20 ATT&CK for ICS techniques, all present in the library's ICS technique data; the library's `superseded_by.jsonl` maps the revoked ids T0803, T0804, T0805, T0855 and T0857 to the T1691, T1692, T1693 and T1695 sub-techniques, so current ids are used (Confirmed [79]; Demonstrated [131]). The library has no generated pages for ICS techniques, so the ids are plain text, with names and tactics from `data/attack/ics/` (Demonstrated [131][134]).

| Id | Name (ATT&CK for ICS v20.0) | Tactic(s) | Basis | Dated event or report | Sources |
|---|---|---|---|---|---|
| T0822 | External Remote Services | initial-access | Listed (C0028) | VPN access to the distribution companies (23 Dec) | [79][78] |
| T0886 | Remote Services | initial-access, lateral-movement | Listed (C0028) | Remote administration tools (23 Dec) | [79][78] |
| T0859 | Valid Accounts | persistence, lateral-movement | Listed (C0028) | Likely legitimate credentials (23 Dec) | [79][78] |
| T0823 | Graphical User Interface | execution | Listed (C0028) | Breakers operated through ICS client software (23 Dec) | [79][78] |
| T0867 | Lateral Tool Transfer | lateral-movement | Listed (C0028) | Ukraine (Dec) | [79] |
| T0846 | Remote System Discovery | discovery | Listed (C0028) | Ukraine (Dec) | [79] |
| T0885 | Commonly Used Port | command-and-control | Listed (C0028) | Ukraine (Dec) | [79] |
| T0884 | Connection Proxy | command-and-control | Listed (C0028) | Ukraine (Dec) | [79] |
| T1693.001 | System Firmware | persistence, inhibit-response-function, impair-process-control | Listed (C0028) | Serial-to-Ethernet firmware corrupted (23 Dec) | [79][78] |
| T1695.001 | Serial COM | inhibit-response-function | Listed (C0028) | Ukraine (Dec) | [79] |
| T1691.001 | Command Message | inhibit-response-function | Listed (C0028) | Ukraine (Dec) | [79] |
| T1691.002 | Reporting Message | inhibit-response-function | Listed (C0028) | Ukraine (Dec) | [79] |
| T0814 | Denial of Service | inhibit-response-function | Listed (C0028) | Ukraine (Dec) | [79] |
| T0816 | Device Restart/Shutdown | inhibit-response-function | Listed (C0028) | Scheduled UPS disconnects (23 Dec) | [79][78] |
| T1692.001 | Command Message | evasion, impair-process-control | Listed (C0028) | Breakers opened remotely (23 Dec) | [79][78] |
| T0813 | Denial of Control | impact | Listed (C0028) | Ukraine (Dec) | [79] |
| T0826 | Loss of Availability | impact | Listed (C0028) | About 225,000 customers without power (23 Dec) | [79][78] |
| T0827 | Loss of Control | impact | Listed (C0028) | Ukraine (Dec) | [79] |
| T0828 | Loss of Productivity and Revenue | impact | Listed (C0028) | Ukraine (Dec) | [79] |
| T0831 | Manipulation of Control | impact | Listed (C0028) | Breakers opened remotely (23 Dec) | [79][78] |

### Enterprise techniques of C0028

The campaign's 17 Enterprise techniques on the live page match the library's `campaign_profiles.jsonl` exactly: T1071.001, T1059.005, T1136.002, T1685, T1133, T1070.004, T1105, T1056.001, T1570, T1112, T1040, T1566.001, T1055, T1018, T1218.011, T1204.002 and T1078 (Confirmed [79]; Demonstrated [131]). All are in the Enterprise table above.

### ATT&CK groups, software and campaigns

| Object | Id | Binding | Sources |
|---|---|---|---|
| 2015 Ukraine Electric Power Attack | [C0028](/mitre/campaigns/C0028.md) | Bound: 17 Enterprise and 20 ICS techniques | [79][131] |
| Sandworm Team | [G0034](/mitre/groups/G0034.md) | Bound through C0028; attributed to GRU unit 74455 | [80][79] |
| BlackEnergy | [S0089](/mitre/software/S0089.md) | Bound through C0028 (BlackEnergy3) | [79] |
| KillDisk | [S0607](/mitre/software/S0607.md) | Bound with a caveat: T1485 and T1561.002 (citations not traced) | [131][78] |
| Equation | [G0020](/mitre/groups/G0020.md) | Bound: four techniques, main source Kaspersky February 2015 | [9][8] |
| Carbanak | [G0008](/mitre/groups/G0008.md); [S0030](/mitre/software/S0030.md) | Bound with a caveat: S0030's T1056.001, T1113, T1021.001, T1219 and T1071.001 | [11][131][10] |
| APT29 | [G0016](/mitre/groups/G0016.md) | Bound: T1566.002 (listing not traced to 2015); DNC from summer 2015 | [57][56] |
| HAMMERTOSS | [S0037](/mitre/software/S0037.md) | Bound: seven techniques, "used by APT29 in 2015" | [59][58] |
| APT28 | [G0007](/mitre/groups/G0007.md) | Bound: T1068 and T1134.001 through CVE-2015-1701; context for the Bundestag and TV5Monde, which its description does not mention | [34][33][22][23] |
| JHUHUGIT | [S0044](/mitre/software/S0044.md) | Bound: T1068 through CVE-2015-1701 and CVE-2015-2387 | [33] |
| Duqu | [S0038](/mitre/software/S0038.md) | Bound: T1134 and T1218.007, citing the Duqu 2.0 paper; no separate Duqu 2.0 entry | [39][38] |
| Hacking Team UEFI Rootkit | [S0047](/mitre/software/S0047.md) | Bound: T1542.001 and T1014 (Trend Micro, 13 Jul 2015) | [102] |
| SYNful Knock | [S0519](/mitre/software/S0519.md) | Bound: T1556.004, T1601.001 and T1205 | [64][63] |
| Dridex | [S0384](/mitre/software/S0384.md) | Bound with a caveat: T1204.002, T1185, T1071.001, T1219 | [131][67] |
| Indrik Spider | [G0119](/mitre/groups/G0119.md) | Context: the library's Dridex operator | [131] |
| Threat Group-3390 | [G0027](/mitre/groups/G0027.md) | Bound with a caveat: T1189 (Secureworks, 5 Aug 2015, not opened) | [90][131] |
| Deep Panda | [G0009](/mitre/groups/G0009.md) | Context only (Reported): ATT&CK's Anthem attribution | [4] |
| Turla | [G0010](/mitre/groups/G0010.md) | Context: Satellite Turla, 9 Sep 2015 | [84][83] |
| APT30 | [G0013](/mitre/groups/G0013.md) | Context: FireEye, April 2015 | [86][85] |
| Naikon | [G0019](/mitre/groups/G0019.md) | Context (Reported attribution): Kaspersky, 14 May 2015; CameraShy, 23 Sep 2015 | [88][87] |
| Lotus Blossom | [G0030](/mitre/groups/G0030.md) | Context: Unit 42, 16 Jun 2015 | [89] |
| APT41; Patchwork; Confucius; Darkhotel; BlackTech; APT3 | [G0096](/mitre/groups/G0096.md); [G0040](/mitre/groups/G0040.md); [G0142](/mitre/groups/G0142.md); [G0012](/mitre/groups/G0012.md); [G0098](/mitre/groups/G0098.md); [G0022](/mitre/groups/G0022.md) | Bound through T1203 procedure rows naming 2015 CVEs; dates of use not checked. APT41's home is [APT41](/case-studies/APT41_PUBLIC_RECORD.md) | [103] |
| Patchwork; RTM; Sowbug; Orangeworm; Ferocious Kitten | [G0040](/mitre/groups/G0040.md); [G0048](/mitre/groups/G0048.md); [G0054](/mitre/groups/G0054.md); [G0071](/mitre/groups/G0071.md); [G0137](/mitre/groups/G0137.md) | Context: the library's ATT&CK data dates each to 2015 (Patchwork first observed December 2015) | [131] |

This study binds no ATT&CK object for Simda, Dorkbot, CryptoWall, Superfish, the Great Cannon or the Impact Team; XcodeGhost exists only as the ATT&CK for Mobile object S0297, which is outside this study's Enterprise and ICS binding, so its Enterprise row above is T1195.001 alone (Demonstrated [131]).

### CWE and CAPEC

The CWE column names the source of each id. Names are those in the library's CWE and CAPEC data, and every CAPEC listed has a page under `/mitre/capec/` (Demonstrated [132][134]). The library has no per-CWE generated pages, so CWE ids are plain text; the [CWE reference](/CWE_REFERENCE.md) is the entry point. NVD assigns the categories CWE-310 and CWE-189, which the library's CWE data does not hold (Confirmed [132]).

| CWE | Weakness (library name) | Basis | 2015 record | CAPEC |
|---|---|---|---|---|
| CWE-787 | Out-of-bounds Write | NVD [7][100] | GHOST CVE-2015-0235 (27 Jan); Word CVE-2015-1641 | None assigned |
| CWE-416 | Use After Free | NVD [43] | Flash CVE-2015-5119 and CVE-2015-5122 (Jul) | None assigned |
| CWE-502 | Deserialization of Untrusted Data | NVD [73] | WebLogic CVE-2015-4852 (Nov) | [CAPEC-586](/mitre/capec/CAPEC-586.md) Object Injection (Inferred) |
| CWE-287 | Improper Authentication | NVD [77] | ScreenOS CVE-2015-7755 (17 Dec) | [CAPEC-115](/mitre/capec/CAPEC-115.md) Authentication Bypass (Inferred; the library relates it to CWE-287) |
| CWE-506 | Embedded Malicious Code | Inferred (NVD does not list it) | Unauthorized code in ScreenOS (17 Dec) | [CAPEC-442](/mitre/capec/CAPEC-442.md) Infected Software (Inferred; the library relates it to CWE-506 and T1195.002) |
| CWE-310 (category), CWE-295 | (not in the library's CWE data); Improper Certificate Validation | NVD (CWE-310); the CNA (CWE-295) [36][14][77] | FREAK CVE-2015-0204; Logjam CVE-2015-4000; ScreenOS CVE-2015-7756 | [CAPEC-620](/mitre/capec/CAPEC-620.md) Drop Encryption Level (on CWE-757 and T1600); [CAPEC-97](/mitre/capec/CAPEC-97.md) Cryptanalysis (on CWE-327); [CAPEC-94](/mitre/capec/CAPEC-94.md) Adversary in the Middle (AiTM) (on T1557) (all Inferred) |
| CWE-94 | Improper Control of Generation of Code | NVD [29] | HTTP.sys CVE-2015-1635 (14 Apr) | None assigned |
| CWE-119 | Improper Restriction of Operations within the Bounds of a Memory Buffer | NVD [35] | VENOM CVE-2015-3456 (13 May) | [CAPEC-100](/mitre/capec/CAPEC-100.md) Overflow Buffers (Inferred) |
| CWE-189 (retired category); CWE-190 | Integer Overflow or Wraparound (CWE-190, the base the library holds) | NVD (CWE-189) [53]; Inferred (CWE-190) | Stagefright CVE-2015-1538 | [CAPEC-92](/mitre/capec/CAPEC-92.md) Forced Integer Overflow (Inferred) |
| CWE-284 | Improper Access Control | NVD [101] | ProFTPD CVE-2015-3306 (18 May) | None assigned |
| CWE-20 | Improper Input Validation | NVD [100] | Joomla CVE-2015-8562 (Dec) | None assigned |
| CWE-89 | Improper Neutralization of Special Elements used in an SQL Command | Inferred (no CVE) | TalkTalk SQL injection (Oct) | [CAPEC-66](/mitre/capec/CAPEC-66.md) SQL Injection (Inferred) |
| none bound | (phishing and credentials) | Library data | Carbanak, Dridex, BlackEnergy and APT29 phishing; the LAPS context | [CAPEC-163](/mitre/capec/CAPEC-163.md) Spear Phishing (on T1566.001); [CAPEC-644](/mitre/capec/CAPEC-644.md) Use of Captured Hashes (Pass The Hash) (on T1550.002, Part 8 context) |

### D3FEND countermeasures

The technique-to-countermeasure links come from the library's D3FEND data (version 1.6.0); pairing them with the 2015 record is this study's reading (Demonstrated [133]; Inferred). Every page exists under `/mitre/d3fend/` (Demonstrated [134]).

| Technique or event from the record | D3FEND countermeasures (D3FEND tactic) | 2015 analogue |
|---|---|---|
| T1542.001, T1542.002, T1542.004 | [Firmware Verification](/mitre/d3fend/firmware-verification.md) (Detect); [System Firmware Verification](/mitre/d3fend/system-firmware-verification.md) (Detect, on T1542.001 and T1542.004); [Firmware Behavior Analysis](/mitre/d3fend/firmware-behavior-analysis.md) (Detect); [Firmware Embedded Monitoring Code](/mitre/d3fend/firmware-embedded-monitoring-code.md) (Detect); [Software Update](/mitre/d3fend/software-update.md) (Harden); [Restore Software](/mitre/d3fend/restore-software.md) (Restore) | Hacking Team UEFI rootkit [102]; Equation disk firmware [8]; Cisco ROMMON [62] |
| T1190 | [Inbound Traffic Filtering](/mitre/d3fend/inbound-traffic-filtering.md) (Isolate); [Network Traffic Signature Analysis](/mitre/d3fend/network-traffic-signature-analysis.md) (Detect); [Database Query String Analysis](/mitre/d3fend/database-query-string-analysis.md) (Detect); [Client-server Payload Profiling](/mitre/d3fend/client-server-payload-profiling.md) (Detect) | TalkTalk [69]; WebLogic [72]; Joomla [100] |
| T1505.003 | [Executable Allowlisting](/mitre/d3fend/executable-allowlisting.md) (Isolate); [File Integrity Monitoring](/mitre/d3fend/file-integrity-monitoring.md) (Detect); [Process Spawn Analysis](/mitre/d3fend/process-spawn-analysis.md) (Detect) | TA15-314A [70] |
| T1203, T1068 | [Process Segment Execution Prevention](/mitre/d3fend/process-segment-execution-prevention.md) (Harden); [Segment Address Offset Randomization](/mitre/d3fend/segment-address-offset-randomization.md) (Harden); [Stack Frame Canary Validation](/mitre/d3fend/stack-frame-canary-validation.md) (Harden); [Shadow Stack Comparisons](/mitre/d3fend/shadow-stack-comparisons.md) (Detect); [Memory Boundary Tracking](/mitre/d3fend/memory-boundary-tracking.md) (Detect); [Process Code Segment Verification](/mitre/d3fend/process-code-segment-verification.md) (Detect) | Flash [43]; IE [98]; Win32k [31] |
| T1566.001, T1566.002 | [Email Filtering](/mitre/d3fend/email-filtering.md) (Isolate); [Content Filtering](/mitre/d3fend/content-filtering.md) (Isolate); [File Analysis](/mitre/d3fend/file-analysis.md) (Detect); [Dynamic Analysis](/mitre/d3fend/dynamic-analysis.md) (Detect); [Sender Reputation Analysis](/mitre/d3fend/sender-reputation-analysis.md) (Detect); [URL Analysis](/mitre/d3fend/url-analysis.md) (Detect, on T1566.002) | Carbanak [10]; Dridex [67]; BlackEnergy [78]; APT29 [56] |
| T1557 | [Network Traffic Signature Analysis](/mitre/d3fend/network-traffic-signature-analysis.md) (Detect); [Network Traffic Filtering](/mitre/d3fend/network-traffic-filtering.md) (Isolate); [Protocol Metadata Anomaly Detection](/mitre/d3fend/protocol-metadata-anomaly-detection.md) (Detect) | FREAK and Logjam [13][37] |
| T1195.001, T1195.002 | [Software Inventory](/mitre/d3fend/software-inventory.md) (Model); [Software Update](/mitre/d3fend/software-update.md) (Harden); [Restore Software](/mitre/d3fend/restore-software.md) (Restore); [Asset Vulnerability Enumeration](/mitre/d3fend/asset-vulnerability-enumeration.md) (Model) | XcodeGhost [65]; ScreenOS [75] |
| T1078, T1133 | [Change Default Password](/mitre/d3fend/change-default-password.md) (Harden, on T1078); [Access Modeling](/mitre/d3fend/access-modeling.md) (Model, on T1078); [Account Locking](/mitre/d3fend/account-locking.md) (Evict, on T1078); [User Account Permissions](/mitre/d3fend/user-account-permissions.md) (Isolate, on T1078); [Session Termination](/mitre/d3fend/session-termination.md) (Evict, on T1133) | Ukraine [78]; Ashley Madison [46]; OPM [26] |
| T1561.002 | [Disk Partitioning](/mitre/d3fend/disk-partitioning.md) (Evict) | KillDisk [78] |
| T1486 | [Restore File](/mitre/d3fend/restore-file.md) (Restore); [File Integrity Monitoring](/mitre/d3fend/file-integrity-monitoring.md) (Detect); [Decoy File](/mitre/d3fend/decoy-file.md) (Deceive) | CryptoWall [40] |
| T1056.001 | [Input Device Analysis](/mitre/d3fend/input-device-analysis.md) (Detect); [IO Port Restriction](/mitre/d3fend/io-port-restriction.md) (Isolate) | Dridex [67]; Carbanak [10] |
| Name-fit only | [Multi-factor Authentication](/mitre/d3fend/multi-factor-authentication.md), [Credential Rotation](/mitre/d3fend/credential-rotation.md), [Credential Hardening](/mitre/d3fend/credential-hardening.md), [Message Encryption](/mitre/d3fend/message-encryption.md) (Inferred fits; the library maps none of them to this study's unmapped techniques) | VPN access, LAPS, export-grade TLS [78][120][37] |

The library links T1550.002, T1556.004, T1601.001, T1600, T1059.001, T1485, T1498, T1070, T1657, T1102.003 and T1001.002 to no D3FEND countermeasure (Demonstrated [133]). ATT&CK mitigation pages exist for every M-id named in Part 8 (Demonstrated [134]).

### Navigator layer

The study's techniques are saved as two ATT&CK Navigator layers pinned to ATT&CK v20, in the format of the existing chronicle layers: the Enterprise layer [navigator/library-layers/chronicle-2015.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/chronicle-2015.json) (domain enterprise-attack: the 57 techniques of the Enterprise table under each tactic they carry in v20.0, 75 technique-tactic entries) and the ICS layer [navigator/case-studies/chronicle-2015-ics.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/case-studies/chronicle-2015-ics.json) (domain ics-attack: the 20 techniques of the ICS table, 25 technique-tactic entries), both described as curated case-study layers and not official MITRE mappings and listed on [the Navigator layers page](/navigator/index.md) (Demonstrated [134]). Scores show the basis, not severity, in the house scale set by the 2016 chronicle: 100 where an ATT&CK object or technique page prints the id (Listed), 70 where a primary source describes the behavior and this study assigns the id (Described), and 40 for an Inferred mapping. In the Enterprise layer 45 techniques score 100; T1190, T1195.001, T1505.003, T1542.004, T1070, T1087.002, T1486, T1498 and T1657 score 70; and T1195.002, T1600 and T1557 score 40. In the ICS layer all 20 techniques score 100. Each entry's comment names the source numbers in the Sources table below.

## Cross-cutting themes

**The data thefts were national in scale.** OPM's background-investigation loss, Anthem's 78.8 million persons (as charged) and Ashley Madison's 36 million accounts put the year's breaches in the tens of millions (Confirmed [26][3][46]).

**Remote access with real credentials carried the year's worst intrusions.** VPN and contractor or employee credentials appear in the Ukrainian, Ashley Madison and OPM records (Confirmed [78][46][26]).

**Attackers worked below the operating system.** Disk firmware, UEFI, ROMMON, router images and firewall code were all reported in one year (Confirmed [8][102][62][63][75]).

**The state named states slowly, and acted by instrument.** Sanctions, an executive order, a bilateral commitment and a UN norms report all date from 2015, while the attributions of the year's intrusions came in 2016, 2020, 2021 and 2025 (Confirmed [5][18][66][109][56][81][78][23]; Inferred for the reading).

**The defender's toolkit became institutional.** Public ATT&CK, the end of RC4 and SSLv3 in BCP 195, free automated certificates, an information-sharing law and order, the federal Sprint, NIST supply-chain, ICS and CUI guidance, Windows 10 and PowerShell v5 logging, and the Wyndham ruling all arrived in 2015 (Confirmed [126][122][123][124][105][20][113][114][115][116][118][119][108]; Inferred for the reading).

**Money moved through email more than through ransom.** IC3's BEC losses were more than 150 times its ransomware losses in 2015 complaints (Confirmed [82]; Inferred for the ratio).

### What is overstated and what is understated

This section is the study's reading of the record (Inferred).

- **Overstated: the branded protocol bugs as measured threats.** FREAK, Logjam, GHOST, VENOM and Stagefright's CVE-2015-1538 dominated coverage, yet none is in KEV, MS15-034 had no known attacks at release, and Logjam's nation-state scenario is the researchers' estimate [14][36][7][35][53][30][37].
- **Overstated: Carbanak's USD 1 billion.** It is Kaspersky's estimate, not a court finding [10].
- **Overstated: the first claim of responsibility for TV5Monde.** The Cyber Caliphate claim came first, but the later government records attribute the sabotage to the GRU [21][22][23].
- **Overstated: the precision of ATT&CK ids on 2015 events.** No 2015 event was mapped at the time; C0028, HAMMERTOSS and SYNful Knock are later bindings, and C0028's ICS ids have been revised [126][79][131].
- **Overstated: IC3 totals as a measure of crime.** They are complaint figures, not total losses [82].
- **Understated: the ordinary exploited bugs.** KEV's 2015 entries are mostly Microsoft, Flash, Office and Java client and server bugs added in 2021 and 2022, and Win32k CVE-2015-1701 carries a ransomware flag [99][31].
- **Understated: the long tail.** ScreenOS CVE-2015-7755 entered KEV only on 2 October 2025 and ProFTPD CVE-2015-3306 on 8 October 2026 [99][101].
- **Understated: implants on network devices and firmware.** ROMMON images, SYNful Knock and ScreenOS drew less attention than the branded bugs, and the library's D3FEND data has no countermeasure for router-image tampering [62][63][75][133].
- **Understated: business email compromise.** BEC's 2015 complaint losses dwarfed ransomware's [82].
- **Understated: the Ukrainian organizations that stayed lit.** Six organizations were intruded, and three had no operational impact, which says the access was wider than the outage [78].
- **Understated: the lag inside OPM.** Fingerprint data appear to have left around 26 March, three weeks before OPM notified US-CERT on 15 April [26].

### Discrepancies in the record

- **The Ukrainian count.** CISA and the 2020 indictment give about or more than 225,000 customers; the UK profile gives 230,000 people (Confirmed [78][81][22]).
- **Stagefright's affected versions.** US-CERT gives Android 2.2 through 5.1.1_r5; CERT/CC gives up to but not including 5.1.1_r9 (Confirmed [51][52]).
- **The executive order numbers.** The White House pages print none; the Federal Register gives 13691 (signed 13 February, published 20 February) and 13694 (signed 1 April, published 2 April) (Confirmed [17][19][18][20]).
- **Logjam's date.** The researchers made it public on 20 May; NVD published the record on 21 May (Confirmed [37][36]).
- **Duqu 2.0's date.** Kaspersky's page is dated 10 June; ATT&CK cites the paper as 11 June (Confirmed [38][39]).
- **The Jeep recall.** Wired says 1.4 million vehicles; NHTSA's recall covers 1,416,903 (Reported [49]; Confirmed [50]).
- **BEC figures.** IC3 gives 7,838 BEC complaints and over USD 263 million, and elsewhere over 8,000 BEC and EAC complaints with nearly USD 275 million combined; adding EAC's 281 complaints and over USD 11 million reconciles them (Confirmed [82]; Inferred for the reconciliation).
- **TalkTalk's count.** The BBC says nearly 157,000 customers; the ICO gives 156,959 (Reported [68]; Confirmed [69]).
- **OPM's home.** This study treats [The Hacker and the State](/case-studies/HACKER_AND_THE_STATE_CASES.md) as the home for OPM; [China-attributed threat actors](/case-studies/THREAT_ACTORS_CHINA.md) also carries it and cites the House report's "a foreign adversary" (Confirmed [135][134]).
- **Windows Server 2003's end.** Microsoft lists 7/15/2015 6:59:59 AM PT, the last moment of 14 July Pacific time (Confirmed [117]; Inferred for the reading).

## Sources

External sources were opened on 12 or 13 November 2026, and the library data checks were run on 12 and 13 November 2026, as the Opened column shows. All are checked as of 13 November 2026. Grade is the source's evidence grade as used in this study. Addresses shown as code rather than as links refuse automated link checkers (the NVD API queries, the sec.gov addresses of Anthem's filings and of the SEC's two press releases, and the ftc.gov VTech release); copy them into a browser to open them.

| # | Source | URL | Opened | Grade |
|---|---|---|---|---|
| 1 | Anthem, Inc., Form 10-K for fiscal 2014, filed 24 Feb 2015 | `https://www.sec.gov/Archives/edgar/data/1156039/000115603915000003/antm-20141231x10k.htm` | 2026-11-12; 2026-11-13 | Confirmed (the company's account) |
| 2 | Anthem, Inc., Form 8-K Exhibit 99.1, filed 18 Feb 2015 | `https://www.sec.gov/Archives/edgar/data/1156039/000119312515051630/d876402dex991.htm` | 2026-11-12 | Confirmed |
| 3 | FBI, wanted notice, Fujie Wang | https://www.fbi.gov/wanted/cyber/fujie-wang | 2026-11-12; 2026-11-13 | Confirmed (as charged) |
| 4 | MITRE ATT&CK, G0009 Deep Panda | https://attack.mitre.org/groups/G0009/ | 2026-11-12; 2026-11-13 | Confirmed (what ATT&CK records); Reported (the attribution) |
| 5 | US Treasury, press release JL9733, 2 Jan 2015 | https://home.treasury.gov/news/press-releases/jl9733 | 2026-11-13 | Confirmed |
| 6 | Qualys, GHOST advisory, CVE-2015-0235, 27 Jan 2015 | https://www.qualys.com/2015/01/27/cve-2015-0235/GHOST-CVE-2015-0235.txt | 2026-11-12; 2026-11-13 | Confirmed |
| 7 | NVD, CVE-2015-0235 (API record) | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2015-0235` | 2026-11-12 | Confirmed |
| 8 | Kaspersky GReAT, Equation: The Death Star of Malware Galaxy, 16 Feb 2015 | https://securelist.com/equation-the-death-star-of-malware-galaxy/68750/ | 2026-11-12; 2026-11-13 | Confirmed (vendor's finding) |
| 9 | MITRE ATT&CK, G0020 Equation | https://attack.mitre.org/groups/G0020/ | 2026-11-12 | Confirmed |
| 10 | Kaspersky, The Great Bank Robbery: Carbanak, press release, 17 Feb 2015 | https://www.kaspersky.com/about/press-releases/2015_the-great-bank-robbery-carbanak-cybergang-steals--1bn-from-100-financial-institutions-worldwide | 2026-11-12; 2026-11-13 | Confirmed (vendor's finding); Reported (the loss estimate) |
| 11 | MITRE ATT&CK, G0008 Carbanak | https://attack.mitre.org/groups/G0008/ | 2026-11-12 | Confirmed |
| 12 | US-CERT (CISA archive), TA15-051A, Lenovo Superfish Adware Vulnerable to HTTPS Spoofing, 20 Feb 2015 | https://www.cisa.gov/news-events/alerts/2015/02/20/lenovo-superfish-adware-vulnerable-https-spoofing | 2026-11-13 | Confirmed |
| 13 | US-CERT (CISA archive), FREAK SSL/TLS Vulnerability, 6 Mar 2015 | https://www.cisa.gov/news-events/alerts/2015/03/06/freak-ssltls-vulnerability | 2026-11-12; 2026-11-13 | Confirmed |
| 14 | NVD, CVE-2015-0204 (API record) | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2015-0204` | 2026-11-12 | Confirmed |
| 15 | GitHub, Large Scale DDoS Attack on github.com, 27 Mar 2015 | https://github.blog/2015-03-27-large-scale-ddos-attack-on-github-com/ | 2026-11-13 | Confirmed |
| 16 | Citizen Lab, China's Great Cannon, 10 Apr 2015 | https://citizenlab.ca/2015/04/chinas-great-cannon/ | 2026-11-13 | Confirmed (researchers' finding) |
| 17 | The White House (archive), Executive Order Blocking the Property of Certain Persons Engaging in Significant Malicious Cyber-Enabled Activities, 1 Apr 2015 | https://obamawhitehouse.archives.gov/the-press-office/2015/04/01/executive-order-blocking-property-certain-persons-engaging-significant-m | 2026-11-12; 2026-11-13 | Confirmed |
| 18 | Federal Register, document 2015-07788 (Executive Order 13694) | https://www.federalregister.gov/api/v1/documents/2015-07788.json | 2026-11-12 | Confirmed |
| 19 | The White House (archive), Executive Order Promoting Private Sector Cybersecurity Information Sharing, 13 Feb 2015 | https://obamawhitehouse.archives.gov/the-press-office/2015/02/13/executive-order-promoting-private-sector-cybersecurity-information-shari | 2026-11-12 | Confirmed |
| 20 | Federal Register, document 2015-03714 (Executive Order 13691) | https://www.federalregister.gov/api/v1/documents/2015-03714.json | 2026-11-12 | Confirmed |
| 21 | BBC News, How France's TV5 was almost destroyed by 'Russian hackers', 10 Oct 2016 | https://www.bbc.com/news/technology-37590375 | 2026-11-13 | Reported |
| 22 | UK Government, Profile: GRU cyber and hybrid threat operations | https://www.gov.uk/government/publications/profile-gru-cyber-and-hybrid-threat-operations/profile-gru-cyber-and-hybrid-threat-operations | 2026-11-12 | Confirmed (the UK government's attribution) |
| 23 | French Ministry for Europe and Foreign Affairs, attribution of cyberattacks against France to the GRU, 29 Apr 2025 | https://www.diplomatie.gouv.fr/en/presse-et-ressources/decouvrir-et-informer/actualites/russie-attribution-de-cyberattaques-contre-la-france-au-service-de-renseignement-militaire-russe | 2026-11-12 | Confirmed |
| 24 | CrowdStrike, Bears in the Midst: Intrusion into the Democratic National Committee, 14 Jun 2016 | https://www.crowdstrike.com/en-us/blog/bears-midst-intrusion-democratic-national-committee/ | 2026-11-12 | Confirmed (its own incident response); Reported (the relayed Bundestag and TV5 Monde linkage) |
| 25 | US-CERT (CISA archive), TA15-105A, Simda Botnet, 15 Apr 2015 | https://www.cisa.gov/news-events/alerts/2015/04/15/simda-botnet | 2026-11-13 | Confirmed |
| 26 | US House Committee on Oversight and Government Reform, Timeline of Key Events (OPM) | https://oversight.house.gov/wp-content/uploads/2016/09/Timeline-of-Key-Events-.pdf | 2026-11-12; 2026-11-13 | Confirmed |
| 27 | US House Committee on Oversight and Government Reform, majority staff report, The OPM Data Breach, 7 Sep 2016 (PDF; title page readable) | https://oversight.house.gov/wp-content/uploads/2016/09/The-OPM-Data-Breach-How-the-Government-Jeopardized-Our-National-Security-for-More-than-a-Generation.pdf | 2026-11-12 | Confirmed |
| 28 | US House Committee on Oversight and Government Reform, report landing page, The OPM Data Breach | https://oversight.house.gov/report/opm-data-breach-government-jeopardized-national-security-generation/ | 2026-11-12 | Confirmed |
| 29 | NVD, CVE-2015-1635 (detail page and API record) | https://nvd.nist.gov/vuln/detail/CVE-2015-1635 ; `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2015-1635` | 2026-11-12; 2026-11-13 | Confirmed |
| 30 | Microsoft, Security Bulletin MS15-034, 14 Apr 2015 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2015/ms15-034 | 2026-11-12 | Confirmed |
| 31 | NVD, CVE-2015-1701 (API record) | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2015-1701` | 2026-11-12 | Confirmed |
| 32 | Microsoft, Security Bulletin MS15-051, 12 May 2015 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2015/ms15-051 | 2026-11-12 | Confirmed |
| 33 | MITRE ATT&CK, T1068 Exploitation for Privilege Escalation | https://attack.mitre.org/techniques/T1068/ | 2026-11-12 | Confirmed |
| 34 | MITRE ATT&CK, G0007 APT28 | https://attack.mitre.org/groups/G0007/ | 2026-11-12 | Confirmed |
| 35 | NVD, CVE-2015-3456 (API record) | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2015-3456` | 2026-11-12 | Confirmed |
| 36 | NVD, CVE-2015-4000 (detail page and API record) | https://nvd.nist.gov/vuln/detail/CVE-2015-4000 ; `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2015-4000` | 2026-11-12; 2026-11-13 | Confirmed |
| 37 | Logjam researchers, Weak Diffie-Hellman and the Logjam Attack | https://weakdh.org/ | 2026-11-12 | Confirmed (dates and advice); Reported (the 8.4% figure and the nation-state estimate) |
| 38 | Kaspersky GReAT, The Mystery of Duqu 2.0, 10 Jun 2015 | https://securelist.com/the-mystery-of-duqu-2-0-a-sophisticated-cyberespionage-actor-returns/70504/ | 2026-11-12; 2026-11-13 | Confirmed (vendor's finding); Reported (the reader-thread CVE comment) |
| 39 | MITRE ATT&CK, S0038 Duqu | https://attack.mitre.org/software/S0038/ | 2026-11-12 | Confirmed |
| 40 | US-CERT (CISA archive), IC3 Issues Alert on CryptoWall Ransomware, 23 Jun 2015 | https://www.cisa.gov/news-events/alerts/2015/06/23/ic3-issues-alert-cryptowall-ransomware | 2026-11-13 | Confirmed |
| 41 | US-CERT (CISA archive), OPM Identity Protection Phishing Campaigns, 30 Jun 2015 | https://www.cisa.gov/news-events/alerts/2015/06/30/opm-identity-protection-phishing-campaigns | 2026-11-13 | Confirmed |
| 42 | Wired, Hacking Team Breach Shows a Global Spying Firm Run Amok, 6 Jul 2015 | https://www.wired.com/2015/07/hacking-team-breach-shows-global-spying-firm-run-amok/ | 2026-11-13 | Reported |
| 43 | NVD, CVE-2015-5119 (detail page and API record; CVE-2015-5122 from its API record) | https://nvd.nist.gov/vuln/detail/CVE-2015-5119 ; `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2015-5119` | 2026-11-12; 2026-11-13 | Confirmed |
| 44 | CERT/CC, VU#561288, Adobe Flash ByteArray use-after-free | https://kb.cert.org/vuls/id/561288 | 2026-11-12 | Confirmed |
| 45 | Microsoft, Security Bulletin MS15-078, 20 Jul 2015 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2015/ms15-078 | 2026-11-12; 2026-11-13 | Confirmed |
| 46 | Office of the Privacy Commissioner of Canada and OAIC, PIPEDA Report of Findings #2016-005 (Ashley Madison), 22 Aug 2016 | https://www.priv.gc.ca/en/opc-actions-and-decisions/investigations/investigations-into-businesses/2016/pipeda-2016-005/ | 2026-11-12; 2026-11-13 | Confirmed |
| 47 | Wired, What happened when hackers posted stolen Ashley Madison data, Aug 2015 | https://www.wired.com/2015/08/happened-hackers-posted-stolen-ashley-madison-data/ | 2026-11-13 | Reported |
| 48 | US-CERT (CISA archive), Fiat Chrysler Automobiles (FCA) Uconnect Vulnerability, 27 Jul 2015 | https://www.cisa.gov/news-events/alerts/2015/07/27/fiat-chrysler-automobiles-fca-uconnect-vulnerability | 2026-11-13 | Confirmed |
| 49 | Wired, Hackers Remotely Kill a Jeep on the Highway, 21 Jul 2015 (updated 24 Jul) | https://www.wired.com/2015/07/hackers-remotely-kill-jeep-highway/ | 2026-11-13 | Reported |
| 50 | NHTSA, recall 15V-461 (API record) | https://api.nhtsa.gov/recalls/campaignNumber?campaignNumber=15V461000 | 2026-11-12 | Confirmed |
| 51 | US-CERT (CISA archive), Stagefright Android Vulnerability, 28 Jul 2015 | https://www.cisa.gov/news-events/alerts/2015/07/28/stagefright-android-vulnerability | 2026-11-13 | Confirmed |
| 52 | CERT/CC, VU#924951, Android Stagefright | https://kb.cert.org/vuls/id/924951 | 2026-11-12 | Confirmed |
| 53 | NVD, CVE-2015-1538 (API record) | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2015-1538` | 2026-11-12 | Confirmed |
| 54 | Android Security Bulletin, August 2015 | https://source.android.com/docs/security/bulletin/2015-08-01 | 2026-11-12 | Confirmed |
| 55 | US-CERT (CISA archive), IC3 Issues Alert on DDoS Extortion Campaigns, 31 Jul 2015 | https://www.cisa.gov/news-events/alerts/2015/07/31/ic3-issues-alert-ddos-extortion-campaigns | 2026-11-13 | Confirmed |
| 56 | DHS and FBI, JAR-16-20296A, GRIZZLY STEPPE, 29 Dec 2016 | https://www.cisa.gov/sites/default/files/publications/JAR_16-20296A_GRIZZLY%20STEPPE-2016-1229.pdf | 2026-11-12; 2026-11-13 | Confirmed |
| 57 | MITRE ATT&CK, G0016 APT29 | https://attack.mitre.org/groups/G0016/ | 2026-11-12 | Confirmed |
| 58 | FireEye, HAMMERTOSS: Stealthy Tactics Define a Russian Cyber Threat Group, Jul 2015 | https://services.google.com/fh/files/misc/rpt-apt29-hammertoss-stealthy-tactics-define-en.pdf | 2026-11-12 | Confirmed (vendor's finding) |
| 59 | MITRE ATT&CK, S0037 HAMMERTOSS | https://attack.mitre.org/software/S0037/ | 2026-11-12 | Confirmed |
| 60 | F-Secure, The Dukes: 7 years of Russian cyberespionage, Sep 2015 | https://www.f-secure.com/documents/996508/1030745/dukes_whitepaper.pdf | 2026-11-12 | Confirmed (vendor's finding) |
| 61 | SEC, press release 2015-163, newswire hacking scheme, 11 Aug 2015 | `https://www.sec.gov/news/pressrelease/2015-163.html` | 2026-11-13 | Confirmed (as charged) |
| 62 | US-CERT (CISA archive), Evolution in Attacks Against Cisco IOS Software Platforms, 12 Aug 2015 | https://www.cisa.gov/news-events/alerts/2015/08/12/evolution-attacks-against-cisco-ios-software-platforms | 2026-11-13 | Confirmed |
| 63 | Mandiant, SYNful Knock: A Cisco router implant, 15 Sep 2015 | https://cloud.google.com/blog/topics/threat-intelligence/synful-knock-acis/ | 2026-11-13 | Confirmed (vendor's finding) |
| 64 | MITRE ATT&CK, S0519 SYNful Knock | https://attack.mitre.org/software/S0519/ | 2026-11-12 | Confirmed |
| 65 | Palo Alto Networks Unit 42, Novel Malware XcodeGhost Modifies Xcode, 17 Sep 2015 | https://unit42.paloaltonetworks.com/novel-malware-xcodeghost-modifies-xcode-infects-apple-ios-apps-and-hits-app-store/ | 2026-11-12; 2026-11-13 | Confirmed (vendor's finding) |
| 66 | The White House (archive), Fact Sheet: President Xi Jinping's State Visit to the United States, 25 Sep 2015 | https://obamawhitehouse.archives.gov/the-press-office/2015/09/25/fact-sheet-president-xi-jinpings-state-visit-united-states | 2026-11-12; 2026-11-13 | Confirmed |
| 67 | US-CERT (CISA archive), TA15-286A, Dridex P2P Malware, 13 Oct 2015 | https://www.cisa.gov/news-events/alerts/2015/10/13/dridex-p2p-malware | 2026-11-12; 2026-11-13 | Confirmed |
| 68 | BBC News, TalkTalk fined record GBP 400,000 for customer data security failings, 5 Oct 2016 | https://www.bbc.com/news/business-37565367 | 2026-11-13 | Reported |
| 69 | ICO, TalkTalk cyber attack: how the ICO's investigation unfolded | https://ico.org.uk/about-the-ico/media-centre/talktalk-cyber-attack-how-the-ico-investigation-unfolded/ | 2026-11-12 | Confirmed |
| 70 | US-CERT (CISA archive), TA15-314A, Compromised Web Servers and Web Shells, 10 Nov 2015 | https://www.cisa.gov/news-events/alerts/2015/11/10/compromised-web-servers-and-web-shells-threat-awareness-and-guidance | 2026-11-12; 2026-11-13 | Confirmed |
| 71 | US-CERT (CISA archive), Apache Commons Collections Java Library Vulnerability, 13 Nov 2015 | https://www.cisa.gov/news-events/alerts/2015/11/13/apache-commons-collections-java-library-vulnerability | 2026-11-13 | Confirmed |
| 72 | Oracle, Security Alert for CVE-2015-4852 | https://www.oracle.com/security-alerts/alert-cve-2015-4852.html | 2026-11-12 | Confirmed |
| 73 | NVD, CVE-2015-4852 (API record) | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2015-4852` | 2026-11-12 | Confirmed |
| 74 | US-CERT (CISA archive), TA15-337A, Dorkbot, 3 Dec 2015 | https://www.cisa.gov/news-events/alerts/2015/12/03/dorkbot | 2026-11-13 | Confirmed |
| 75 | US-CERT (CISA archive), Juniper Releases Out-of-Band Security Advisory for ScreenOS, 17 Dec 2015 | https://www.cisa.gov/news-events/alerts/2015/12/17/juniper-releases-out-band-security-advisory-screenos | 2026-11-13 | Confirmed |
| 76 | CERT/CC, VU#640184, Juniper ScreenOS | https://kb.cert.org/vuls/id/640184 | 2026-11-12 | Confirmed |
| 77 | NVD, CVE-2015-7755 and CVE-2015-7756 (API records) | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2015-7755` | 2026-11-12 | Confirmed |
| 78 | ICS-CERT (CISA), IR-ALERT-H-16-056-01, Cyber-Attack Against Ukrainian Critical Infrastructure (updated 20 Jul 2021) | https://www.cisa.gov/news-events/ics-alerts/ir-alert-h-16-056-01 | 2026-11-12; 2026-11-13 | Confirmed |
| 79 | MITRE ATT&CK, C0028 2015 Ukraine Electric Power Attack | https://attack.mitre.org/campaigns/C0028/ | 2026-11-12; 2026-11-13 | Confirmed |
| 80 | MITRE ATT&CK, G0034 Sandworm Team | https://attack.mitre.org/groups/G0034/ | 2026-11-12 | Confirmed |
| 81 | US District Court, W.D. Pa., indictment No. 20-316, filed 15 Oct 2020 | https://www.justice.gov/opa/press-release/file/1328521/download | 2026-11-12 | Confirmed (as charged) |
| 82 | FBI IC3, 2015 Internet Crime Report | https://www.ic3.gov/AnnualReport/Reports/2015_IC3Report.pdf | 2026-11-12; 2026-11-13 | Confirmed |
| 83 | Kaspersky GReAT, Satellite Turla: APT Command and Control in the Sky, 9 Sep 2015 | https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/ | 2026-11-12 | Confirmed (vendor's finding) |
| 84 | MITRE ATT&CK, G0010 Turla | https://attack.mitre.org/groups/G0010/ | 2026-11-12 | Confirmed |
| 85 | FireEye, APT30 and the Mechanics of a Long-Running Cyber Espionage Operation, Apr 2015 (hosted copy) | https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2015/05/20081935/rpt-apt30.pdf | 2026-11-12 | Confirmed (vendor's finding) |
| 86 | MITRE ATT&CK, G0013 APT30 | https://attack.mitre.org/groups/G0013/ | 2026-11-12 | Confirmed |
| 87 | Kaspersky GReAT, The Naikon APT, 14 May 2015 | https://securelist.com/the-naikon-apt/69953/ | 2026-11-12 | Confirmed (vendor's finding) |
| 88 | MITRE ATT&CK, G0019 Naikon | https://attack.mitre.org/groups/G0019/ | 2026-11-12 | Confirmed (what ATT&CK records); Reported (the attribution) |
| 89 | Palo Alto Networks Unit 42, Operation Lotus Blossom, 16 Jun 2015 | https://www.paloaltonetworks.com/resources/research/unit42-operation-lotus-blossom.html | 2026-11-12 | Confirmed (vendor's finding) |
| 90 | MITRE ATT&CK, G0027 Threat Group-3390 | https://attack.mitre.org/groups/G0027/ | 2026-11-12 | Confirmed (what ATT&CK records) |
| 91 | US District Court, C.D. Cal., criminal complaint against Park Jin Hyok, filed 8 Jun 2018 | https://www.justice.gov/opa/press-release/file/1092091/download | 2026-11-12 | Confirmed (as charged) |
| 92 | CISA and partners, AA20-239A, FASTCash 2.0: North Korea's BeagleBoyz Robbing Banks, 26 Aug 2020 | https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-239a | 2026-11-12 | Confirmed |
| 93 | US Court of Appeals, Second Circuit, United States v. Ulbricht, No. 15-1815, 31 May 2017 (Justia) | https://law.justia.com/cases/federal/appellate-courts/ca2/15-1815/15-1815-2017-05-31.html | 2026-11-12 | Confirmed |
| 94 | FBI, Cyber Criminal Forum Taken Down, 15 Jul 2015 | https://www.fbi.gov/news/stories/cyber-criminal-forum-taken-down | 2026-11-12 | Confirmed |
| 95 | Microsoft, Security Bulletin MS15-135 (and the 2015 bulletin series) | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2015/ms15-135 | 2026-11-12 | Confirmed |
| 96 | Microsoft, Security Bulletin MS15-011, 10 Feb 2015 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2015/ms15-011 | 2026-11-12 | Confirmed |
| 97 | US-CERT (CISA archive), TA15-119A, Top 30 Targeted High Risk Vulnerabilities, 29 Apr 2015 | https://www.cisa.gov/news-events/alerts/2015/04/29/top-30-targeted-high-risk-vulnerabilities | 2026-11-12 | Confirmed |
| 98 | Microsoft, Security Bulletin MS15-093, 18 Aug 2015 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2015/ms15-093 | 2026-11-12 | Confirmed |
| 99 | CISA, Known Exploited Vulnerabilities catalog (JSON feed) | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | 2026-11-12 | Confirmed |
| 100 | NVD, CVE-2015-1641 and the other 2015 records named in Part 3 (API records) | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2015-1641` | 2026-11-12 | Confirmed |
| 101 | NVD, CVE-2015-3306 (API record) | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2015-3306` | 2026-11-12 | Confirmed |
| 102 | MITRE ATT&CK, S0047 Hacking Team UEFI Rootkit | https://attack.mitre.org/software/S0047/ | 2026-11-12 | Confirmed |
| 103 | MITRE ATT&CK, T1203 Exploitation for Client Execution | https://attack.mitre.org/techniques/T1203/ | 2026-11-12 | Confirmed |
| 104 | Federal Register, BIS proposed rule 2015-11642 (search result and document record) | https://www.federalregister.gov/api/v1/documents/2015-11642.json ; https://www.federalregister.gov/api/v1/documents.json?conditions%5Bterm%5D=intrusion+software&conditions%5Bagencies%5D%5B%5D=industry-and-security-bureau&conditions%5Bpublication_date%5D%5Byear%5D=2015 | 2026-11-12 | Confirmed |
| 105 | GovInfo, Public Law 114-113, Consolidated Appropriations Act, 2016 | https://www.govinfo.gov/content/pkg/PLAW-114publ113/html/PLAW-114publ113.htm | 2026-11-12 | Confirmed |
| 106 | CISA, Cybersecurity Information Sharing Act of 2015 Procedures and Guidance | https://www.cisa.gov/resources-tools/resources/cybersecurity-information-sharing-act-2015-procedures-and-guidance | 2026-11-12 | Confirmed |
| 107 | Court of Justice of the European Union, press release No 117/15, Schrems, 6 Oct 2015 | https://curia.europa.eu/jcms/upload/docs/application/pdf/2015-10/cp150117en.pdf | 2026-11-12 | Confirmed |
| 108 | US Court of Appeals, Third Circuit, FTC v. Wyndham Worldwide Corp., No. 14-3514, 24 Aug 2015 | https://www2.ca3.uscourts.gov/opinarch/143514p.pdf | 2026-11-12 | Confirmed |
| 109 | United Nations, A/70/174, Report of the Group of Governmental Experts, 22 Jul 2015 | https://documents.un.org/doc/undoc/gen/n15/228/35/pdf/n1522835.pdf | 2026-11-12 | Confirmed |
| 110 | IRS, Statement on the Get Transcript Application, 26 May 2015 | https://www.irs.gov/newsroom/irs-statement-on-the-get-transcript-application | 2026-11-12 | Confirmed |
| 111 | FTC, Electronic Toy Maker VTech Settles FTC Allegations, 8 Jan 2018 | `https://www.ftc.gov/news-events/news/press-releases/2018/01/electronic-toy-maker-vtech-settles-ftc-allegations-it-violated-childrens-privacy-law-ftc-act` | 2026-11-12 (could not be reopened 2026-11-13) | Reported |
| 112 | SEC, press release 2015-202, R.T. Jones Capital Equities Management, 22 Sep 2015 | `https://www.sec.gov/newsroom/press-releases/2015-202` | 2026-11-12 | Confirmed |
| 113 | OMB, M-16-04, Cybersecurity Strategy and Implementation Plan, 30 Oct 2015 | https://obamawhitehouse.archives.gov/sites/default/files/omb/memoranda/2016/m-16-04.pdf | 2026-11-12 | Confirmed |
| 114 | NIST, SP 800-161, 8 Apr 2015 | https://csrc.nist.gov/pubs/sp/800/161/final | 2026-11-12 | Confirmed |
| 115 | NIST, SP 800-82 Rev. 2, May 2015 | https://csrc.nist.gov/pubs/sp/800/82/r2/final | 2026-11-12 | Confirmed |
| 116 | NIST, SP 800-171, 18 Jun 2015 | https://csrc.nist.gov/pubs/sp/800/171/final | 2026-11-12 | Confirmed |
| 117 | Microsoft Learn, Windows Server 2003 lifecycle | https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2003- | 2026-11-12 | Confirmed |
| 118 | Microsoft Learn, Windows 10 Enterprise and Education lifecycle | https://learn.microsoft.com/en-us/lifecycle/products/windows-10-enterprise-and-education | 2026-11-12 | Confirmed |
| 119 | Microsoft PowerShell team, PowerShell the Blue Team, 9 Jun 2015 | https://devblogs.microsoft.com/powershell/powershell-the-blue-team/ | 2026-11-12 | Confirmed |
| 120 | Microsoft Download Center, Local Administrator Password Solution | https://www.microsoft.com/en-us/download/details.aspx?id=46899 | 2026-11-12 | Confirmed |
| 121 | IETF, RFC 7465, Prohibiting RC4 Cipher Suites, Feb 2015 | https://www.rfc-editor.org/rfc/rfc7465.txt | 2026-11-12 | Confirmed |
| 122 | IETF, RFC 7525 (BCP 195), May 2015 | https://www.rfc-editor.org/rfc/rfc7525.txt | 2026-11-12 | Confirmed |
| 123 | IETF, RFC 7568, Deprecating SSL 3.0, Jun 2015 | https://www.rfc-editor.org/rfc/rfc7568.txt | 2026-11-12 | Confirmed |
| 124 | Let's Encrypt, Our First Certificate Is Now Live, 14 Sep 2015 | https://letsencrypt.org/2015/09/14/our-first-cert.html | 2026-11-12 | Confirmed |
| 125 | Let's Encrypt, Entering Public Beta, 3 Dec 2015 | https://letsencrypt.org/2015/12/03/entering-public-beta.html | 2026-11-12 | Confirmed |
| 126 | MITRE, ATT&CK: Design and Philosophy, March 2020 (PDF) | https://attack.mitre.org/docs/ATTACK_Design_and_Philosophy_March_2020.pdf | 2026-11-12 | Confirmed |
| 127 | MITRE ATT&CK, version history | https://attack.mitre.org/resources/versions/ | 2026-11-12 | Confirmed |
| 128 | CVE Program, CVE ID syntax change (archive) | https://www.cve.org/Resources/Media/Archives/OldWebsite/cve/identifiers/syntaxchange.html | 2026-11-12 | Confirmed |
| 129 | MITRE CWE, News Archive 2015 | https://cwe.mitre.org/news/archives/news2015.html | 2026-11-12 | Confirmed |
| 130 | MITRE CAPEC, News Archive 2015 | https://capec.mitre.org/news/archives/news2015.html | 2026-11-12 | Confirmed |
| 131 | TeamStarWolf library, ATT&CK and ICS data (`data/attack/`, `data/attack/ics/`, including `groups.jsonl`, `software.jsonl`, `group_to_technique.jsonl`, `software_to_technique.jsonl`, `campaigns.jsonl`, `campaign_profiles.jsonl`, `technique_profiles.jsonl` and `superseded_by.jsonl`) | https://github.com/TeamStarWolf/TeamStarWolf/tree/main/data/attack | 2026-11-12; 2026-11-13 | Confirmed (what ATT&CK records); Demonstrated (this study's checks); Inferred (the study's reading of attribution timing) |
| 132 | TeamStarWolf library, weakness data (`data/weaknesses/cwe.jsonl`, `data/weaknesses/capec.jsonl`) | https://github.com/TeamStarWolf/TeamStarWolf/tree/main/data/weaknesses | 2026-11-12; 2026-11-13 | Demonstrated |
| 133 | TeamStarWolf library, D3FEND data (`data/attack/d3fend_countermeasures.jsonl`, `data/attack/technique_to_d3fend.jsonl`) | https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/data/attack/technique_to_d3fend.jsonl | 2026-11-12; 2026-11-13 | Demonstrated |
| 134 | TeamStarWolf library, repository tree (`mitre/` technique, group, software, campaign, CAPEC, D3FEND and mitigation pages; `navigator/` layers; `case-studies/THREAT_ACTORS_CHINA.md`) | https://api.github.com/repos/TeamStarWolf/TeamStarWolf/git/trees/main?recursive=1 | 2026-11-12; 2026-11-13 | Demonstrated |
| 135 | TeamStarWolf library, case studies on main (home studies named in the text: `HACKER_AND_THE_STATE_CASES.md`, `THREAT_ACTORS_CHINA.md`, `SANDWORM_OPERATIONS.md`, `THREAT_ACTORS_RUSSIA.md`, `FANCY_BEAR_GOES_PHISHING_CASES.md`, `ZERO_DAY_MARKET_EVENTS.md`, `STUXNET.md`, `THREAT_ACTORS_UNITED_STATES.md`, `THREAT_ACTORS_OTHER_STATES.md`, `THREAT_ACTORS_NORTH_KOREA.md`, `ECOMMERCE_THREATS.md`, `PROFTPD_MOD_COPY_CVE_2015_3306.md`) | https://github.com/TeamStarWolf/TeamStarWolf/tree/main/case-studies | 2026-11-12; 2026-11-13 | Confirmed (for the fact that a study is the home and for the facts it carries from its own sources, at the grade it gives them); Demonstrated (this study's checks) |

*© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.*

*© The MITRE Corporation. Includes material from the Common Weakness Enumeration (CWE™), used under the CWE Terms of Use. https://cwe.mitre.org/*

*© The MITRE Corporation. Includes material from the Common Attack Pattern Enumeration and Classification (CAPEC™), used under the CAPEC Terms of Use. https://capec.mitre.org/*

*© The MITRE Corporation. Includes material from MITRE D3FEND™, used under the D3FEND Terms of Use. https://d3fend.mitre.org/*

*The terms for every MITRE dataset used here are recorded in [THIRD_PARTY_NOTICES.md](/THIRD_PARTY_NOTICES.md).*

## Related references

- [Notable Incidents](/NOTABLE_INCIDENTS.md), [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [CVE Reference](/CVE_REFERENCE.md)
- [Threat Intelligence](/THREAT_INTELLIGENCE_REFERENCE.md), [Cryptography](/CRYPTOGRAPHY_REFERENCE.md), [Web Application Security](/WEB_APPLICATION_SECURITY_REFERENCE.md), [Email Security](/EMAIL_SECURITY_REFERENCE.md), [Identity and Access Management](/IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md), [Supply Chain Security](/SUPPLY_CHAIN_SECURITY_REFERENCE.md), [Firmware and IoT Security](/FIRMWARE_IOT_SECURITY_REFERENCE.md), [Automotive Security](/AUTOMOTIVE_SECURITY_REFERENCE.md), [Mobile Security](/MOBILE_SECURITY_REFERENCE.md), [Ransomware Defense](/RANSOMWARE_DEFENSE_REFERENCE.md), [CWE Reference](/CWE_REFERENCE.md), [CAPEC Reference](/CAPEC_REFERENCE.md), [D3FEND Reference](/D3FEND_REFERENCE.md), [GRC and Compliance](/GRC_COMPLIANCE_REFERENCE.md), [Vulnerability Management](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [Incident Response](/INCIDENT_RESPONSE_REFERENCE.md), [ICS/OT Security](/ICS_OT_SECURITY_REFERENCE.md)
- Home studies: [The Hacker and the State](/case-studies/HACKER_AND_THE_STATE_CASES.md); [China-attributed threat actors](/case-studies/THREAT_ACTORS_CHINA.md); [APT41](/case-studies/APT41_PUBLIC_RECORD.md); [Sandworm Operations](/case-studies/SANDWORM_OPERATIONS.md); [Russia-attributed threat actors](/case-studies/THREAT_ACTORS_RUSSIA.md); [Fancy Bear Goes Phishing](/case-studies/FANCY_BEAR_GOES_PHISHING_CASES.md); [North Korea-attributed threat actors](/case-studies/THREAT_ACTORS_NORTH_KOREA.md); [Other states' threat actors](/case-studies/THREAT_ACTORS_OTHER_STATES.md); [United States-attributed threat actors](/case-studies/THREAT_ACTORS_UNITED_STATES.md); [The Zero-Day Market](/case-studies/ZERO_DAY_MARKET_EVENTS.md); [NSA and CIA tool leaks](/case-studies/NSA_CIA_TOOL_LEAKS.md); [Stuxnet](/case-studies/STUXNET.md); [E-Commerce Threats](/case-studies/ECOMMERCE_THREATS.md); [ProFTPD mod_copy](/case-studies/PROFTPD_MOD_COPY_CVE_2015_3306.md); [Ransomware ecosystem](/case-studies/RANSOMWARE_ECOSYSTEM.md); [ICS attacks and advisories](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md); [Log4Shell](/case-studies/LOG4SHELL.md); [SolarWinds SUNBURST](/case-studies/SOLARWINDS_SUNBURST.md); [npm supply-chain attacks](/case-studies/NPM_SUPPLY_CHAIN_ATTACKS.md); [Hugging Face supply chain](/case-studies/HUGGING_FACE_SUPPLY_CHAIN.md); [The Year 2014 in Intrusions](/case-studies/CHRONICLE_2014.md) (the Sony Pictures attack behind the January 2015 sanctions and the 2014 OPM intrusions, before the 2015 notices)
- Series: [1993](/case-studies/CHRONICLE_1993.md), [1994](/case-studies/CHRONICLE_1994.md), [1995](/case-studies/CHRONICLE_1995.md), [1996](/case-studies/CHRONICLE_1996.md), [1997](/case-studies/CHRONICLE_1997.md), [1998](/case-studies/CHRONICLE_1998.md), [1999](/case-studies/CHRONICLE_1999.md), [2000](/case-studies/CHRONICLE_2000.md), [2001](/case-studies/CHRONICLE_2001.md), [2002](/case-studies/CHRONICLE_2002.md), [2003](/case-studies/CHRONICLE_2003.md), [2004](/case-studies/CHRONICLE_2004.md), [2005](/case-studies/CHRONICLE_2005.md), [2006](/case-studies/CHRONICLE_2006.md), [2007](/case-studies/CHRONICLE_2007.md), [2008](/case-studies/CHRONICLE_2008.md), [2009](/case-studies/CHRONICLE_2009.md), [2010](/case-studies/CHRONICLE_2010.md), [2011](/case-studies/CHRONICLE_2011.md), [2012](/case-studies/CHRONICLE_2012.md), [2013](/case-studies/CHRONICLE_2013.md), [2014](/case-studies/CHRONICLE_2014.md), [2016](/case-studies/CHRONICLE_2016.md), [2017](/case-studies/CHRONICLE_2017.md), [2018](/case-studies/CHRONICLE_2018.md), [2019](/case-studies/CHRONICLE_2019.md), [2020](/case-studies/CHRONICLE_2020.md), [2021](/case-studies/CHRONICLE_2021.md), [2022](/case-studies/CHRONICLE_2022.md), [2023](/case-studies/CHRONICLE_2023.md), [2024](/case-studies/CHRONICLE_2024.md), [2025](/case-studies/CHRONICLE_2025.md), [2026](/case-studies/CHRONICLE_2026.md)
- Techniques: [T1133 External Remote Services](/mitre/techniques/T1133.md), [T1078 Valid Accounts](/mitre/techniques/T1078.md), [T1566.001 Spearphishing Attachment](/mitre/techniques/T1566-001.md), [T1566.002 Spearphishing Link](/mitre/techniques/T1566-002.md), [T1190 Exploit Public-Facing Application](/mitre/techniques/T1190.md), [T1203 Exploitation for Client Execution](/mitre/techniques/T1203.md), [T1068 Exploitation for Privilege Escalation](/mitre/techniques/T1068.md), [T1542.001 System Firmware](/mitre/techniques/T1542-001.md), [T1542.002 Component Firmware](/mitre/techniques/T1542-002.md), [T1542.004 ROMMONkit](/mitre/techniques/T1542-004.md), [T1556.004 Network Device Authentication](/mitre/techniques/T1556-004.md), [T1601.001 Patch System Image](/mitre/techniques/T1601-001.md), [T1195.001 Compromise Software Dependencies and Development Tools](/mitre/techniques/T1195-001.md), [T1195.002 Compromise Software Supply Chain](/mitre/techniques/T1195-002.md), [T1505.003 Web Shell](/mitre/techniques/T1505-003.md), [T1485 Data Destruction](/mitre/techniques/T1485.md), [T1561.002 Disk Structure Wipe](/mitre/techniques/T1561-002.md), [T1486 Data Encrypted for Impact](/mitre/techniques/T1486.md), [T1657 Financial Theft](/mitre/techniques/T1657.md), [T1102.003 One-Way Communication](/mitre/techniques/T1102-003.md); the full list is in the Part 9 table
- CAPEC: [CAPEC-586](/mitre/capec/CAPEC-586.md), [CAPEC-115](/mitre/capec/CAPEC-115.md), [CAPEC-442](/mitre/capec/CAPEC-442.md), [CAPEC-620](/mitre/capec/CAPEC-620.md), [CAPEC-97](/mitre/capec/CAPEC-97.md), [CAPEC-94](/mitre/capec/CAPEC-94.md), [CAPEC-100](/mitre/capec/CAPEC-100.md), [CAPEC-92](/mitre/capec/CAPEC-92.md), [CAPEC-66](/mitre/capec/CAPEC-66.md), [CAPEC-163](/mitre/capec/CAPEC-163.md), [CAPEC-644](/mitre/capec/CAPEC-644.md)
- Campaign, groups and software: [C0028](/mitre/campaigns/C0028.md); Sandworm Team [G0034](/mitre/groups/G0034.md); BlackEnergy [S0089](/mitre/software/S0089.md); KillDisk [S0607](/mitre/software/S0607.md); Equation [G0020](/mitre/groups/G0020.md); Carbanak [G0008](/mitre/groups/G0008.md) and [S0030](/mitre/software/S0030.md); APT29 [G0016](/mitre/groups/G0016.md); HAMMERTOSS [S0037](/mitre/software/S0037.md); APT28 [G0007](/mitre/groups/G0007.md); JHUHUGIT [S0044](/mitre/software/S0044.md); Duqu [S0038](/mitre/software/S0038.md); Hacking Team UEFI Rootkit [S0047](/mitre/software/S0047.md); SYNful Knock [S0519](/mitre/software/S0519.md); Dridex [S0384](/mitre/software/S0384.md); Indrik Spider [G0119](/mitre/groups/G0119.md); Threat Group-3390 [G0027](/mitre/groups/G0027.md); Deep Panda [G0009](/mitre/groups/G0009.md); Turla [G0010](/mitre/groups/G0010.md); APT30 [G0013](/mitre/groups/G0013.md); Naikon [G0019](/mitre/groups/G0019.md); Lotus Blossom [G0030](/mitre/groups/G0030.md); APT41 [G0096](/mitre/groups/G0096.md); Patchwork [G0040](/mitre/groups/G0040.md); Confucius [G0142](/mitre/groups/G0142.md); Darkhotel [G0012](/mitre/groups/G0012.md); BlackTech [G0098](/mitre/groups/G0098.md); APT3 [G0022](/mitre/groups/G0022.md); RTM [G0048](/mitre/groups/G0048.md); Sowbug [G0054](/mitre/groups/G0054.md); Orangeworm [G0071](/mitre/groups/G0071.md); Ferocious Kitten [G0137](/mitre/groups/G0137.md)
- [Navigator layers](/navigator/index.md), including this study's layers, [chronicle-2015.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/chronicle-2015.json) and [chronicle-2015-ics.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/case-studies/chronicle-2015-ics.json)
