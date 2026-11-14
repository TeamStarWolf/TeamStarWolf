# The Year 2013 in Intrusions: A Dated Record

*A TeamStarWolf case study. Published 13 November 2026; every source checked as of that date.*

[All case studies](/case-studies/README.md) · Related: [Notable Incidents](/NOTABLE_INCIDENTS.md), [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [CVE Reference](/CVE_REFERENCE.md), [Threat Intelligence](/THREAT_INTELLIGENCE_REFERENCE.md), [Browser Security](/BROWSER_SECURITY_REFERENCE.md), [Cryptography](/CRYPTOGRAPHY_REFERENCE.md), [GRC and Compliance](/GRC_COMPLIANCE_REFERENCE.md), [Incident Response](/INCIDENT_RESPONSE_REFERENCE.md), [Vulnerability Management](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [Ransomware Defense](/RANSOMWARE_DEFENSE_REFERENCE.md), [ICS/OT Security](/ICS_OT_SECURITY_REFERENCE.md) · Home studies for events summarized here: [China-attributed threat actors](/case-studies/THREAT_ACTORS_CHINA.md) (APT1), [APT41](/case-studies/APT41_PUBLIC_RECORD.md) (Winnti Group), [North Korea-attributed threat actors](/case-studies/THREAT_ACTORS_NORTH_KOREA.md) (the March 2013 South Korea attack and Kimsuky), [Iran-attributed threat actors](/case-studies/THREAT_ACTORS_IRAN.md) (the 2011 to 2013 financial-sector DDoS and the Bowman Avenue Dam), [Russia-attributed threat actors](/case-studies/THREAT_ACTORS_RUSSIA.md) (Gamaredon), [Other states' threat actors](/case-studies/THREAT_ACTORS_OTHER_STATES.md) (Molerats and FinFisher), [United States-attributed threat actors](/case-studies/THREAT_ACTORS_UNITED_STATES.md) (the Snowden documents and the Equation exploit list), [The Hacker and the State](/case-studies/HACKER_AND_THE_STATE_CASES.md) (Belgacom and the 2013 press reports), [The Zero-Day Market](/case-studies/ZERO_DAY_MARKET_EVENTS.md), [E-Commerce Threats](/case-studies/ECOMMERCE_THREATS.md) (Target), [The Year 2016 in Intrusions](/case-studies/CHRONICLE_2016.md) and [The Year 2017 in Intrusions](/case-studies/CHRONICLE_2017.md) (the Yahoo theft of August 2013) · Series: [The Year 2012 in Intrusions](/case-studies/CHRONICLE_2012.md), [The Year 2016 in Intrusions](/case-studies/CHRONICLE_2016.md) and the other years in the [case studies index](/case-studies/README.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Threat intelligence analysts, security historians, vulnerability management, payment-card, finance and ICS teams and anyone who wants the history behind current threats

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Beginner to intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 76 min (17,458 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want a dated record of the intrusions of 2013, you need APT1, Red October, MiniDuke, Winnti, NetTraveler, Kimsuky and Icefog side by side with the Spamhaus reflection attack, the Target, Adobe and Yahoo breaches, the year's exploited Java, Internet Explorer, Reader and Office flaws, the Citadel, ZeroAccess, Liberty Reserve and Silk Road actions, CryptoLocker, the executive order and the standards that followed, or you want the defender lessons that still apply

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [Part 2: China-attributed espionage](#part-2-china-attributed-espionage), [Part 6: the vulnerability record](#part-6-the-vulnerability-record)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Notable Incidents](/NOTABLE_INCIDENTS.md), [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md), [E-Commerce Threats](/case-studies/ECOMMERCE_THREATS.md), [The Year 2012 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2012.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive summary

Defenders started 2013 by turning off a browser plug-in. On 10 January US-CERT warned that a Java 7 Security Manager bypass, CVE-2013-0422, was being actively exploited with public exploit code, and NVD records that the Blackhole and Nuclear Pack exploit kits used it that month; Oracle's fix raised Java's default security level to High (Confirmed [2][3][69]). Four days later Kaspersky published Red October, an espionage campaign against diplomatic, government and research bodies, mostly in Eastern Europe, the former USSR and Central Asia, with registration data and timestamps pointing back to May 2007 (Confirmed [1]). Kaspersky said it strongly believed the operators were Russian-speaking and that there was no evidence linking the campaign to a nation state (Confirmed that Kaspersky says so [1]; the judgment is Reported).

February made attribution public. On 30 January The New York Times reported that intruders had been inside its systems for four months and had taken employee passwords, and that its consultants, Mandiant, traced the traffic through compromised US university computers (Reported [5]). On 19 February Mandiant published its APT1 report: 141 victim organizations across 20 industries since 2006, hundreds of terabytes stolen, evidence it said linked APT1 to the PLA General Staff Department's 3rd Department, 2nd Bureau (Military Cover Designator 61398), and more than 3,000 indicators released for defenders (Confirmed as Mandiant's findings [43][121]). ATT&CK records APT1 as G0006 with that unit attribution, and 22 of its technique entries cite the report (Confirmed [10]). The same month the White House issued Executive Order 13636, which set NIST to build the framework published as Cybersecurity Framework 1.0 in February 2014, and Presidential Policy Directive 21 on critical infrastructure (Confirmed [96][7][8]). On 11 March the National Security Advisor called on Beijing to address cyber intrusions "emanating from China" (Confirmed [44]). The home for APT1 is [China-attributed threat actors](/case-studies/THREAT_ACTORS_CHINA.md).

Espionage reporting widened through the year. Kaspersky and CrySyS described MiniDuke, delivered through an Adobe Reader zero-day (27 February), and Kaspersky published Winnti (April), NetTraveler (June), Kimsuky (September) and Icefog (September) (Confirmed [52][16][46][50][31]). ATT&CK later tied MiniDuke to APT29, which it attributes to Russia's SVR on the strength of 2021 government statements, and dates the APT29 campaign Operation Ghost (C0023) from September 2013 (Confirmed [53][54]). The FBI said in December 2014 that tools used against Sony resembled those of a March 2013 attack on South Korean banks and media that North Korea carried out (Confirmed [49]).

Denial of service and crimeware grew. Spamhaus came under a DDoS that peaked at 120 Gbps at Cloudflare's network on 22 March, with DNS reflection as its largest source, and US-CERT warned about open resolvers a week later (Confirmed [13][12][14]). The Iranian campaign against US banks, which a 2016 indictment alleges ran from 2011 through 2013, continued (Confirmed as alleged [27]). CryptoLocker surfaced, encrypting local, network, USB and some cloud-synced files (Confirmed [35]). Microsoft and partners disrupted Citadel in June and ZeroAccess in December, Treasury and prosecutors shut Liberty Reserve in May, and federal prosecutors in New York seized Silk Road on 30 September and arrested its alleged operator on 1 October (Confirmed [23][41][22][66][67]).

Data loss arrived at scale, though some of it was found only years later. Adobe disclosed in October that information on 2.9 million customers was removed and source code for numerous products was accessed (Confirmed [32]). Target confirmed on 19 December that about 40 million card accounts may have been affected, after the Department of Justice told it of the breach on 12 December (Confirmed [40][122]). Yahoo's August 2013 theft, disclosed in December 2016, was later judged to have likely affected every account that existed at the time (Confirmed as the company's account [89][92][26]). The DOE Inspector General reported that a July 2013 intrusion took personal data on more than 104,000 people (Confirmed [25]).

This study records the year by date. It is built only from sources opened on 12 November 2026 (seven NVD records, rows 128 to 134, on 13 November 2026) and from checks of the library's data run on 12 and 13 November 2026, and is checked as of 13 November 2026.

### Key facts at a glance

| Field | Value |
|---|---|
| Period | 1 January to 31 December 2013, plus the records that open, close or explain a 2013 event: Red October's activity from 2007, the 2014 Senate Target report, the 2014 Silk Road indictment, the 2014 CryptoLocker and GameOver Zeus disruption, the FBI's 2014 Sony statement, the 2016 Iran indictment, the 2016 and 2017 Yahoo filings, ESET's 2019 Operation Ghost report and KEV additions from 2022 to 2025 |
| Espionage reports | Red October (14 Jan); NYT intrusion (30 Jan, Reported); APT1 (19 Feb); MiniDuke (27 Feb); Winnti (11 Apr); NetTraveler (4 Jun); Molerats (23 Aug, as ATT&CK cites); Kimsuky (11 Sep); Icefog (25 Sep); Operation Ghost first seen (Sep) (Confirmed [1][43][52][16][46][57][50][31][54]; Reported [5]) |
| State statements | EO 13636 and PPD-21 (12 Feb); Joint Indicator Bulletin (22 Feb); Donilon on China (11 Mar); UN GGE report (24 Jun) (Confirmed [96][7][9][44][102]) |
| Leak journalism | Guardian on the Verizon order and PRISM (6 Jun); Der Spiegel on Belgacom (20 Sep) and TAO (29 Dec) (Reported [60][61][62][63]) |
| Denial of service | Spamhaus (18 to 22 Mar, 120 Gbps at Cloudflare); TA13-088A (29 Mar); bank DDoS 2011 to 2013, as alleged (Confirmed [13][14]; Confirmed as alleged [27]) |
| Breaches | DOE MIS (Jul, 104,000+ people); Yahoo (Aug, likely all accounts then existing); Adobe (3 Oct, 2.9 million customers); Target (27 Nov to 18 Dec, about 40 million cards that may have been affected) (Confirmed [25][26][92][32][40]) |
| Crimeware and takedowns | Liberty Reserve (24 to 28 May); Citadel (5 Jun, 1,462 botnets); Silk Road (30 Sep to 25 Oct); CryptoLocker (TA13-309A, 5 Nov); ZeroAccess (5 Dec, 2 million+ computers) (Confirmed [66][22][23][67][35][41]) |
| Exploited in 2013 per the vendor, US-CERT or NVD | Java CVE-2013-0422 (Jan); ColdFusion CVE-2013-0625 (Jan); Reader CVE-2013-0640 (Feb); IE CVE-2013-1347 (May); IE CVE-2013-3893 and CVE-2013-3897 (Sep to Oct); Office and Windows CVE-2013-3906 (Nov); ActiveX CVE-2013-3918 (Nov); NDProxy CVE-2013-5065 (Nov); WinVerifyTrust CVE-2013-3900 (Dec) (Confirmed [3][72][73][20][81][36][38][39][133][86]) |
| KEV tail | 38 CVE-2013 entries in catalog 2026.11.10, six flagged with known ransomware use; CVE-2013-3893 added 2025-08-12 and CVE-2013-3918 added 2025-10-06 (Confirmed [4]) |
| Microsoft's year | MS13-001 (8 Jan) to MS13-106 (10 Dec): 106 bulletins by numbering (Confirmed [87]; count Inferred) |
| Industrial systems | ICS-CERT responded to 256 incidents, 59 percent in energy; DNP3 advisories in Nov and Dec; Bowman Avenue Dam intrusion (late 2013, as alleged) (Confirmed [95][28]) |
| Policy and standards | HIPAA Omnibus rule (25 Jan); EC3 opens (11 Jan); EU strategy and NIS proposal (7 Feb); SP 800-53 Rev. 4 (Apr); CVE syntax vote (May); RFC 6962 (Jun); Microsoft bounties (19 Jun); SP 800-40 Rev. 3, SP 800-83 Rev. 1, FIPS 186-4 (Jul); SP 800-63-2 (Aug); ISO/IEC 27002:2013 (Oct); Tallinn Manual (2013) (Confirmed [99][100][101][98][111][115][116][106][107][109][108][110][103]) |
| This study's MITRE binding | 60 ATT&CK Enterprise techniques in 70 technique-tactic entries: 44 listed by ATT&CK for objects tied to 2013 reports or events (G0006, G0044, S0033, G0094, S0051, G0021, S0027, S0041), 14 described by a primary and assigned here, two supported only by a Reported source; four ATT&CK for ICS techniques, all Inferred; CWE ids from NVD and KEV; CAPEC and D3FEND pairings from the library's data; one Enterprise Navigator layer (Part 11) |

### Key findings

- **The browser plug-in was the year's front door.** Java CVE-2013-0422 was exploited by exploit kits in January, Java CVE-2013-2465 and IE CVE-2013-2551 carry KEV's known-ransomware flag, and US-CERT tied a May drive-by on two news sites to a Fiesta kit that used a 2013 Java flaw (Confirmed [3][4][21]).
- **Attribution by a private responder changed the conversation.** Mandiant's APT1 report named a PLA unit and released more than 3,000 indicators, and three weeks later the White House spoke publicly about intrusions emanating from China (Confirmed [43][121][44]).
- **Most 2013 espionage reports named no state.** Kaspersky's Red October, NetTraveler and Icefog reports name none, and its Kimsuky report calls North Korean basing "the likely theory"; the state links came later from ATT&CK, the FBI and governments (Confirmed [1][46][31][50][53][49]).
- **Internet Explorer zero-days and watering holes recurred.** Microsoft and US-CERT recorded IE zero-days used against IE8 in May and September, and a November watering hole on a US site specializing in security policy (Confirmed [19][29][37]).
- **DDoS grew by reflection.** Spamhaus was hit mostly by DNS reflection, US-CERT named open resolvers as the amplifier, and a Tier 1 provider reportedly saw more than 300 Gbps (Confirmed [12][14]; Reported [13]).
- **Ransomware moved from lock screens to encryption.** US-CERT warned of DHS-themed lock-screen ransomware in March and of CryptoLocker's file encryption in November (Confirmed [11][35]).
- **Takedowns went after money as well as malware.** Treasury used Section 311 against a virtual currency provider for the first time, and prosecutors seized about 173,991 bitcoins tied to Silk Road (Confirmed [22][67]).
- **The year's breaches surfaced late.** Target learned of its breach from the Justice Department, and Yahoo disclosed its August 2013 theft in December 2016, and Verizon's filing widened it in 2017 (Confirmed [40][89][92]).
- **Industrial incidents were common and poorly logged.** ICS-CERT responded to 256 incidents, and 120 were indeterminate, often for lack of logs (Confirmed [95]).
- **No 2013 event had a contemporaneous ATT&CK mapping, and most KEV entries came nine years later.** ATT&CK was not published in 2013, and most 2013 KEV rows were added in 2022 (Confirmed [4]; Inferred [10]).

### Top recommendations

1. **Remove or restrict browser plug-ins.** US-CERT advised disabling Java in browsers for CVE-2013-0422, and Oracle's fix raised the default security level to High (Confirmed [2][69]).
2. **Close open DNS resolvers and filter spoofed traffic.** TA13-088A describes how open resolvers and spoofed source addresses amplify DDoS, and Spamhaus's attackers used exactly that (Confirmed [14][12]).
3. **Apply vendor workarounds while a fix is pending.** Microsoft's Fix it shim for CVE-2013-3893, which US-CERT said prevents exploitation, was available three weeks before MS13-080 (Confirmed [29][81]).
4. **Keep offline backups.** US-CERT's first CryptoLocker mitigation was offline backups, since the malware encrypts mapped network shares and some cloud-synced folders (Confirmed [35]).
5. **Limit and monitor third-party network access.** The Senate report, relying on press accounts, says Target's attackers entered through access given to an HVAC vendor (Reported [40]).
6. **Take management interfaces off the internet.** US-CERT advised restricting IPMI to management addresses and warned that an ePO exploit tool could execute commands on managed systems (Confirmed [80][24]).
7. **Retire unsupported applications that face the internet.** The DOE system breached in July 2013 had direct internet access without adequate controls, and core support for it had ended in July 2012 (Confirmed [25]).
8. **Use indicator releases quickly.** The APT1 report released more than 3,000 indicators and said its view was a small fraction of APT1's activity (Confirmed [121]).
9. **Stop default and weak administrator passwords.** The WordPress campaign guessed passwords for accounts named "admin" (Confirmed [17]).
10. **Do not read KEV dates as event dates.** CVE-2013-3893 was exploited in September 2013 and added to KEV in August 2025 (Confirmed [29][4]).

## Scope and method

This study covers intrusions, malware, denial of service, vulnerabilities, data breaches, crimeware and takedowns, prosecutions, state and espionage operations, industrial-control incidents and advisories, and regulation, standards and policy dated to 2013, plus the later records that open, close or explain a 2013 event. It follows the method of the [case studies collection](/case-studies/README.md): primary sources first, every claim graded, and numbers given as the source states them. Every external source was opened on 12 November 2026, as the Sources table shows, and the library data checks were run on 12 and 13 November 2026.

| Grade | Meaning in this study |
|---|---|
| Confirmed | The primary record was opened and states the fact: a vendor advisory, bulletin or blog, a company's own statement or SEC filing, a CERT/CC, US-CERT, ICS-CERT or CISA record, a CVE or NVD record, the KEV catalog, an FBI, Justice Department, Treasury or Inspector General record, a congressional staff report, a White House, Federal Register, EU or UN record, a NIST, ISO, IETF or MITRE record, a researchers' or vendor's report stated as its own finding, a live ATT&CK page, or a library study, only for the fact that it is the home for an event |
| Reported | Only a secondary source supports the fact, or a source relays someone else's claim or gives an attribution or estimate that is its own assessment: The New York Times and its consultants on its own intrusion, The Guardian and Der Spiegel on the Snowden documents, KrebsOnSecurity on Target, Cloudflare relaying a Tier 1 provider's figure, the Senate report's reliance on press accounts for Target's point of entry, and Microsoft's loss estimates for Citadel. The source is named in the text |
| Demonstrated | A check this study ran itself and saw the result: id, name, tactic, CAPEC, D3FEND and page checks in the library's data files and `mitre/` tree |
| Inferred | The study's own reading, labelled where it appears. Every ATT&CK, CAPEC and D3FEND id bound to a 2013 event is Inferred as to the binding unless ATT&CK lists it for the object, and so is every CWE that neither NVD nor KEV lists |

Charges, complaints and indictments are allegations; where this study cites one, the record confirms that the charge was made, not that it was proven. Company statements are the company's own account, and vendor and researcher attributions are those authors' assessments, not government findings.

Limits a reader should know:

- **CVE existed; ATT&CK and KEV did not.** Every 2013 product flaw here carries a CVE id. No 2013 record carries an ATT&CK technique id: ATT&CK was published later, and every technique id in Part 11 is assigned in hindsight, either from a later ATT&CK object that cites a 2013 report or by this study (Inferred). KEV's 38 CVE-2013 entries were added from 2022 to 2025 (Confirmed [4]).
- **Some events have no ATT&CK object.** Red October, Icefog, Citadel, CryptoLocker, Reveton, the Blackhole and Fiesta kits, the ITSecTeam and Mersad campaign and the Syrian Electronic Army have no object in the library's ATT&CK data (Confirmed [1][31]; Demonstrated [123]).
- **One report came from a copy.** Mandiant's APT1 report was read as a PDF hosted by Google; one research pass could not open it, and the figures here come from the copy that opened (Confirmed [121]; Demonstrated [10]).
- **What was not checked.** No primary was opened, or the page would not open, for: the FireEye Operation DeputyDog post and the FireEye Operation Molerats report (ATT&CK cites the latter); the Villeneuve et al. Operation Ke3chang report; a 2013 primary for the date and impact of the South Korea attack; the Syrian Electronic Army's hijack of a news agency's Twitter account; the watering-hole victim site of May 2013; Oracle's date for its CVE-2013-0422 alert; the publication month of ISO/IEC 27001:2013; the citations behind ATT&CK's NetTraveler, Zeroaccess, Wiper and FinFisher entries; the later appellate history of the Auernheimer case; and Silk Road's later trial outcome. They are left out or marked "not checked" where they touch a verified fact. Their absence here is not evidence that nothing happened.

## Part 1: the year as a dated timeline

One row per event or report. The date is the event date where the source gives one, otherwise the publication date. Rows marked "frame" or "boundary" open or close a 2013 event.

| Date | Event | Thread | Sector | Grade | Sources |
|---|---|---|---|---|---|
| 2007-05 (frame) | Earliest Red October activity, by registration data and PE timestamps | Espionage | Diplomatic, government, research | Confirmed (vendor's finding) | [1] |
| 2011 (frame) | Icefog tracked from 2011; Kaspersky's Winnti research begins in autumn 2011; the FBI opens its GameOver Zeus investigation (Sep) | Espionage; Crimeware | Defense, maritime, telecom; games; finance | Confirmed | [31][16][83] |
| 2011 to 2013 (frame) | DDoS on the US financial sector by ITSecTeam and Mersad employees, as alleged in 2016. Home: [Iran-attributed threat actors](/case-studies/THREAT_ACTORS_IRAN.md) | DDoS | Finance | Confirmed (as alleged) | [27] |
| 2011-09 to 2014-01 (frame) | Syrian Electronic Army attacks on US government, media and private organizations, as alleged | Hacktivism (state-aligned) | Government; media | Confirmed (as alleged) | [59] |
| 2012-09 to 2013-01 (frame) | Intruders inside The New York Times for four months, per the paper | Espionage | Media | Reported | [5] |
| 2012-10 (frame) | Kaspersky begins the Red October investigation | Espionage | Diplomatic, government, research | Confirmed | [1] |
| 2013-01-08 | Rails 3.2.11, 3.1.10, 3.0.19 and 2.3.15 fix CVE-2013-0155 and CVE-2013-0156; MS13-001, the year's first Microsoft bulletin | Vulnerability | Software | Confirmed | [71][87] |
| 2013-01-10 | US-CERT TA13-010A: Java 7 Security Manager bypass CVE-2013-0422 actively exploited; NVD publishes the CVE; CERT/CC VU#625617 | Vulnerability | Cross-sector | Confirmed | [2][3][70] |
| 2013-01 | Java CVE-2013-0422 exploited by Blackhole and Nuclear Pack; ColdFusion CVE-2013-0625 exploited | Vulnerability | Cross-sector | Confirmed | [3][72] |
| 2013-01-11 | European Cybercrime Centre (EC3) opens at Europol | Policy | Cross-sector | Confirmed | [100] |
| 2013-01-14 | Kaspersky publishes Red October (Rocra) | Espionage | Diplomatic, government, research | Confirmed (vendor's finding) | [1] |
| 2013-01-25 | HIPAA Omnibus final rule published (effective 26 Mar; compliance by 23 Sep) | Policy | Healthcare | Confirmed | [99] |
| 2013-01-30 | The New York Times reports the intrusion and Mandiant's finding of routing through US university computers | Espionage | Media | Reported | [5] |
| 2013-02-04 | Lucky Thirteen: plaintext recovery against TLS and DTLS CBC-mode ciphersuites | Vulnerability | Internet | Confirmed | [117] |
| 2013-02-07 | EU cybersecurity strategy and proposed NIS directive | Policy | Energy, transport, banking, health | Confirmed | [101] |
| 2013-02-12 | Executive Order 13636 and PPD-21 issued | Policy | Critical infrastructure | Confirmed | [96][7] |
| 2013-02-14 | NVD record date for Reader and Acrobat CVE-2013-0640, which NVD says was exploited in the wild | Vulnerability | Cross-sector | Confirmed | [73] |
| 2013-02-19 | Mandiant's APT1 report; EO 13636 published at 78 FR 11739 | Espionage; Policy | 20 industries; Critical infrastructure | Confirmed | [43][121][6] |
| 2013-02-21 | CWE 2.4; CWSS and CWRAF briefed at the DHS Software Assurance Summit | Standards | Software | Confirmed | [113] |
| 2013-02-22 | DHS and FBI Joint Indicator Bulletin on theft of intellectual property and trade secrets (revised 1 Mar) | Guidance | Government; private sector | Confirmed | [9] |
| 2013-02-26 | NIST Request for Information for the framework (270+ responses) | Policy | Critical infrastructure | Confirmed | [97] |
| 2013-02-27 | Kaspersky and CrySyS publish MiniDuke (59 victims in 23 countries) | Espionage | Government | Confirmed (vendors' findings) | [52] |
| 2013-03 | VUPEN demonstrates IE CVE-2013-2551 at Pwn2Own, CanSecWest. Related: [The Zero-Day Market](/case-studies/ZERO_DAY_MARKET_EVENTS.md), which covers the exploit market but not this demonstration | Vulnerability | Cross-sector | Confirmed | [74] |
| 2013-03 | Attack on South Korean banks and media outlets, attributed to North Korea by the FBI in December 2014 (day not checked at a primary). Home: [North Korea-attributed threat actors](/case-studies/THREAT_ACTORS_NORTH_KOREA.md) | Destructive | Finance; media | Confirmed (FBI attribution, 2014) | [49][15] |
| 2013-03-11 | National Security Advisor Donilon on intrusions emanating from China | Policy | Cross-sector | Confirmed | [44] |
| 2013-03-13 | Citizen Lab finds FinSpy servers in 25 countries; Royal Holloway publishes on RC4 in TLS and WPA | Surveillance; Vulnerability | Civil society; Internet | Confirmed | [64][119] |
| 2013-03-15 | CVE-2013-2566 (RC4 biases) published | Vulnerability | Internet | Confirmed | [120] |
| 2013-03-18 | Auernheimer sentenced to 41 months for the AT&T iPad data breach; Spamhaus contacts Cloudflare (Cloudflare's second post) | Crime and courts; DDoS | Telecom; Internet | Confirmed | [94][13] |
| 2013-03-19 to 2013-03-22 | Spamhaus DDoS peaks near 90 Gbps (19 Mar) and at 120 Gbps (22 Mar) at Cloudflare's network | DDoS | Internet | Confirmed (Cloudflare's measurements) | [13][12] |
| 2013-03-21 | US-CERT: DHS-themed lock-screen ransomware (revised 29 Jul) | Crimeware | Consumer | Confirmed | [11] |
| 2013-03-27 | Cloudflare relays a Tier 1 provider's figure of more than 300 Gbps | DDoS | Internet | Reported | [13] |
| 2013-03-29 | US-CERT TA13-088A, DNS Amplification Attacks | DDoS | Internet | Confirmed | [14] |
| 2013-04 | NIST SP 800-53 Rev. 4; first CVE Editorial Board vote on the ID syntax ties | Standards | Government; Cross-sector | Confirmed | [98][111] |
| 2013-04-03 | First NIST framework workshop | Policy | Critical infrastructure | Confirmed | [97] |
| 2013-04-08 | CAPEC 2.0 | Standards | Software | Confirmed | [114] |
| 2013-04-11 | Kaspersky publishes Winnti | Espionage; Crime | Online games | Confirmed (vendor's finding) | [16] |
| 2013-04-15 | US-CERT: mass brute-force botnet against WordPress admin panels | Crimeware | Web | Confirmed | [17] |
| 2013-04-25 | FISA Court order on Verizon call metadata granted, per The Guardian | Surveillance | Telecom | Reported | [60] |
| 2013-04-30 | Citizen Lab finds FinFisher servers in 36 countries and a Malaysian election-themed FinSpy sample | Surveillance | Civil society; politics | Confirmed | [65] |
| 2013-05 | Second CVE Board vote decides the new ID syntax | Standards | Cross-sector | Confirmed | [111] |
| 2013-05-03 | Microsoft Security Advisory 2847140: IE8 CVE-2013-1347 | Vulnerability | Cross-sector | Confirmed | [18] |
| 2013-05-06 to 2013-05-07 | CERT/CC VU#237655; US-CERT alert on attacks against the IE8 flaw | Vulnerability | Cross-sector | Confirmed | [76][19] |
| 2013-05-14 | MS13-038 fixes CVE-2013-1347; record date of Linux perf CVE-2013-2094 | Vulnerability | Cross-sector | Confirmed | [75][77] |
| 2013-05-16 | federalnewsradio.com and wtop.com found redirecting IE users to the Fiesta kit, which delivered a ZeroAccess variant (TA13-141A, 20 May) | Malware | Media | Confirmed | [21] |
| 2013-05-24 to 2013-05-28 | Liberty Reserve: five arrests (24 May); SDNY indictment unsealed and Treasury Section 311 finding (28 May) | Crime and courts | Finance | Confirmed (as charged) | [66][22] |
| 2013-05-29 to 2013-05-31 | Second NIST framework workshop | Policy | Critical infrastructure | Confirmed | [97] |
| 2013-06 | RFC 6962, Certificate Transparency (Experimental) | Standards | Internet | Confirmed | [115] |
| 2013-06-04 | Kaspersky publishes NetTraveler (350+ victims in 40 countries) | Espionage | Government; activists; energy | Confirmed (vendor's finding) | [46] |
| 2013-06-05 | Microsoft and partners disrupt Citadel (Operation b54) | Takedown | Finance | Confirmed | [23][104] |
| 2013-06-06 | The Guardian publishes the Verizon order and the PRISM slides. Home: [The Hacker and the State](/case-studies/HACKER_AND_THE_STATE_CASES.md) | Surveillance | Telecom; Internet | Reported | [60][61] |
| 2013-06-18 | Record date of Java SE CVE-2013-2465 | Vulnerability | Cross-sector | Confirmed | [78] |
| 2013-06-19 | Microsoft announces its standing Mitigation Bypass Bounty (up to USD 100,000), a BlueHat Bonus for defensive ideas accompanying a qualifying bypass (up to USD 50,000) and a 30-day IE11 Preview bug bounty (up to USD 11,000) | Vulnerability research | Software | Confirmed | [116] |
| 2013-06-21 | CAPEC 2.1 | Standards | Software | Confirmed | [114] |
| 2013-06-24 | UN Group of Governmental Experts report A/68/98 | Policy | International | Confirmed | [102] |
| 2013-07 | DOE MIS intrusion exfiltrates PII on 104,000+ people; SP 800-40 Rev. 3, SP 800-83 Rev. 1 and FIPS 186-4 published; Apache Struts S2-016 (CVE-2013-2251) | Breach; Standards; Vulnerability | Government; Cross-sector | Confirmed | [25][106][107][109][79] |
| 2013-07-01 | NIST preliminary framework draft (NIST's wording) | Policy | Critical infrastructure | Confirmed | [97] |
| 2013-07-10 to 2013-07-12 | Third NIST framework workshop | Policy | Critical infrastructure | Confirmed | [97] |
| 2013-07-12 | US-CERT TA13-193A: exploit tool targets McAfee ePO | Vulnerability | Cross-sector | Confirmed | [24] |
| 2013-07-17 | CWE 2.5 (mobile and OWASP Top Ten 2013 entries) | Standards | Software | Confirmed | [113] |
| 2013-07-25 | D.N.J. makes public the Drinkman indictment (160 million+ card numbers) | Crime and courts | Retail; payments; finance | Confirmed (as charged) | [68] |
| 2013-07-26 | US-CERT TA13-207A on IPMI exposure | Vulnerability | Cross-sector | Confirmed | [80] |
| 2013-08 | Yahoo user data stolen (disclosed 14 Dec 2016); SP 800-63-2 published. Home: [2016 chronicle](/case-studies/CHRONICLE_2016.md) | Breach; Standards | Internet; Government | Confirmed | [89][108] |
| 2013-08-23 | FireEye's Operation Molerats report, as ATT&CK cites it | Espionage | Government | Confirmed (that ATT&CK cites it) | [57] |
| 2013-08-28 | NIST framework discussion draft | Policy | Critical infrastructure | Confirmed | [97] |
| 2013-09 | Operation Ghost (C0023) first seen, per ATT&CK | Espionage | Foreign ministries | Confirmed | [54] |
| 2013-09-06 | CVE announces the ID syntax change for 1 January 2014 | Standards | Cross-sector | Confirmed | [112] |
| 2013-09-11 | Kaspersky publishes Kimsuky | Espionage | Government; think tanks; shipping | Confirmed (vendor's finding) | [50] |
| 2013-09-11 to 2013-09-13 | Fourth NIST framework workshop | Policy | Critical infrastructure | Confirmed | [97] |
| 2013-09-17 to 2013-09-18 | Microsoft Security Advisory 2887505 on IE CVE-2013-3893; US-CERT alert on targeted attacks against IE8 and IE9 | Vulnerability | Cross-sector | Confirmed | [30][29] |
| 2013-09-20 | Der Spiegel: Snowden documents indicate GCHQ was behind the Belgacom intrusion | Espionage | Telecom | Reported | [62] |
| 2013-09-25 | Kaspersky publishes Icefog | Espionage | Defense, shipbuilding, telecom, media | Confirmed (vendor's finding) | [31] |
| 2013-09-30 to 2013-10-01 | Silk Road civil forfeiture filed and site seized (30 Sep); Ulbricht arrested in San Francisco (1 Oct) | Crime and courts | Online markets | Confirmed (as charged) | [67][93] |
| 2013-10 | ISO/IEC 27002:2013 published | Standards | Cross-sector | Confirmed | [110] |
| 2013-10-03 | Adobe discloses customer data and source-code compromise; US-CERT alert | Breach | Software | Confirmed | [32][33] |
| 2013-10-08 | MS13-080 fixes CVE-2013-3893 and CVE-2013-3897, both under targeted attack | Vulnerability | Cross-sector | Confirmed | [81] |
| 2013-10-18 | US-CERT: D-Link router firmware backdoor (VU#248083; revised 21 Oct) | Vulnerability | Consumer; small business | Confirmed | [34] |
| 2013-10-25 | A further ~144,336 bitcoins seized, ~173,991 in total | Crime and courts | Online markets | Confirmed (as charged) | [67] |
| 2013-10-29 | NIST Request for Comments on the Preliminary Framework (200+ comments) | Policy | Critical infrastructure | Confirmed | [97] |
| 2013-11 | NDProxy CVE-2013-5065 and ActiveX CVE-2013-3918 exploited in the wild | Vulnerability | Cross-sector | Confirmed | [39][133][38] |
| 2013-11-05 | US-CERT TA13-309A, CryptoLocker; Microsoft Security Advisory 2896666 on TIFF CVE-2013-3906 | Crimeware; Vulnerability | Cross-sector | Confirmed | [35][36] |
| 2013-11-12 | Microsoft's November bulletins patch a watering hole on a US security-policy website | Espionage; Vulnerability | Policy research | Confirmed | [37] |
| 2013-11-14 | Microsoft's Cybercrime Center opens | Takedown | Cross-sector | Confirmed | [41] |
| 2013-11-14 to 2013-11-15 | Fifth NIST framework workshop | Policy | Critical infrastructure | Confirmed | [97] |
| 2013-11-19 to 2013-12-18 | DNP3 advisories: Catapult and GE Proficy (19 Nov), ICSA-13-291-01A (21 Nov), Cooper Cybectec (12 Dec), NovaTech Orion (18 Dec) | ICS | Energy | Confirmed | [95] |
| 2013-11-27 to 2013-12-18 | Cards used in Target's US stores exposed. Home: [E-Commerce Threats](/case-studies/ECOMMERCE_THREATS.md) | Breach | Retail | Confirmed | [40] |
| 2013-11-28 | US-CERT: Microsoft Advisory 2914486 on a Windows XP and Server 2003 kernel flaw under targeted attack | Vulnerability | Cross-sector | Confirmed | [39] |
| 2013-12-05 | Microsoft, the FBI, Europol and partners disrupt ZeroAccess | Takedown | Advertising; consumer | Confirmed | [41] |
| 2013-12-06 | DOE Inspector General report IG-0900 | Breach | Government | Confirmed | [25] |
| 2013-12-09 | CVE List published in CVRF format | Standards | Cross-sector | Confirmed | [112] |
| 2013-12-10 | MS13-096 (CVE-2013-3906), MS13-098 (CVE-2013-3900) and MS13-106, the year's last bulletin | Vulnerability | Cross-sector | Confirmed | [36][86][87] |
| 2013-12-12 | Department of Justice tells Target of the breach | Breach | Retail | Confirmed | [40] |
| 2013-12-18 | KrebsOnSecurity reports the Target investigation; CAPEC 2.2 | Breach; Standards | Retail; Software | Reported; Confirmed | [88][114] |
| 2013-12-19 | Target confirms about 40 million card accounts | Breach | Retail | Confirmed | [40][122] |
| 2013-12-29 | Der Spiegel on NSA's TAO and the QUANTUM tools | Espionage | Telecom; energy | Reported | [63] |
| late 2013 | Intrusion into the Bowman Avenue Dam SCADA systems in Rye, New York, as alleged | ICS | Water | Confirmed (as alleged) | [28] |
| 2014-01 to 2014-02 (boundary) | CVE syntax takes effect (1 Jan); Target discloses data on up to 70 million customers (10 Jan); MS14-002 (14 Jan); Ulbricht indictment release (4 Feb); Cybersecurity Framework 1.0 (12 Feb) | Standards; Breach; Vulnerability; Courts; Policy | Cross-sector | Confirmed | [111][40][85][93][8] |
| 2014 to 2017 (boundary) | Senate Target report (26 Mar 2014); CryptoLocker servers seized (2 Jun 2014); SEA complaint (12 Jun 2014); FBI Sony statement (19 Dec 2014); Iran DDoS indictment (21 Jan 2016); Yahoo 8-K (14 Dec 2016); Verizon 8-K (3 Oct 2017) | Courts; Breach; Takedown | Cross-sector | Confirmed | [40][82][59][49][27][89][92] |

## Part 2: China-attributed espionage

### APT1 (summary)

The home study for APT1 is [China-attributed threat actors](/case-studies/THREAT_ACTORS_CHINA.md), which carries the group's PLA unit attribution in its table of groups (Confirmed that the home study carries it [127]). This chronicle records the 2013 report.

Mandiant's report, announced on 19 February, counts 141 compromised organizations across 20 industries since 2006 and hundreds of terabytes stolen, and presents "evidence linking APT1" to the PLA General Staff Department's 3rd Department, 2nd Bureau, Military Cover Designator 61398 (Confirmed as Mandiant's findings [43][121]). Mandiant released more than 3,000 indicators (domains, IP addresses and MD5 hashes), 13 X.509 certificates and descriptions of more than 40 malware families, and the report says the activity it observed likely represents only a small fraction of APT1's operations (Confirmed [43][121]). The report uses no formal confidence scale (Confirmed [43]). ATT&CK records APT1 as G0006, also called Comment Crew, Comment Group and Comment Panda, attributed to Unit 61398 (Confirmed [10]). It lists 23 techniques and 17 software objects for G0006; 22 of the technique entries cite the Mandiant report, and the 23rd, T1021.001, cites a 2014 FireEye source and is not bound here (Confirmed [10]; Demonstrated [123]).

The same weeks brought the government's response. DHS and the FBI released a TLP-green Joint Indicator Bulletin through secure channels on actors stealing intellectual property and trade secrets from US government and private-sector entities, and then a second bulletin (Confirmed [9]). On 11 March National Security Advisor Tom Donilon cited targeted theft of business information "through cyber intrusions emanating from China on an unprecedented scale", asked Beijing to investigate and stop it, and proposed a direct dialogue on norms (Confirmed [44]). His language is geographic and names no unit (Confirmed [44]).

### The New York Times

The New York Times reported on 30 January that intruders had persistently attacked it for four months and obtained passwords for reporters and other employees, including the e-mail of its Shanghai bureau chief, in the period of its reporting on the family of Wen Jiabao (Reported [5]). Mandiant, hired by the paper, said the intruders routed through compromised US university computers (Reported [5]). The intrusion is the victim's own statement, and the attribution to Chinese hackers is the paper's and its consultants' assessment, not a government record (Reported [5]). ATT&CK's G0005 APT12 cites only a CrowdStrike report and not this case, so no group is bound (Demonstrated [123]).

### Winnti

Kaspersky's April report describes a group "which has Chinese origins" that attacks the online video game industry to steal game source code and legitimate vendors' code-signing certificates; it was first seen through a trojan pushed from a game publisher's official update server, PlugX was also observed, and Kaspersky's research began in autumn 2011 (Confirmed as Kaspersky's findings [16]). Kaspersky framed the group as commercially motivated, not as a state actor (Confirmed [16]). ATT&CK records Winnti Group as G0044, of Chinese origin and active since at least 2010, and all six of its technique entries cite the April 2013 report: T1583.001, T1083, T1105, T1057, T1014 Rootkit and T1553.002 Code Signing (Confirmed [45]). Its software includes S0141 Winnti for Windows and S0013 PlugX (Confirmed [45]). The [APT41](/case-studies/APT41_PUBLIC_RECORD.md) study is the home for how the Winnti name maps onto later clusters (Confirmed that the home study carries it [127]).

### NetTraveler and Icefog

Kaspersky's NetTraveler report of 4 June counts more than 350 high-profile victims in 40 countries, led by Mongolia, India and Russia, including Tibetan and Uyghur activists, oil companies, embassies and military contractors (Confirmed as Kaspersky's findings [46]). Most samples were built from 2010 to 2013, spearphishing used CVE-2012-0158 and CVE-2010-3333, and Kaspersky estimated about 50 operators, "most of which speak Chinese natively", without naming a state (Confirmed [46]). ATT&CK records NetTraveler as S0033 with T1010 Application Window Discovery and T1056.001 Keylogging and associates it with G0062 TA459 (Confirmed [47]).

Kaspersky's Icefog report of 25 September covers a "relatively small group" tracked since 2011 and framed as cyber-mercenaries running hit-and-run operations against supply-chain targets in South Korea and Japan: government, military contractors, maritime and shipbuilding, telecom, satellite operators and media (Confirmed as Kaspersky's findings [31]). It used spearphishing lure documents with known exploits including CVE-2012-0158 and CVE-2013-0422, and tools for Windows and Mac OS X (Confirmed [31]). No state is named, and ATT&CK has no Icefog object (Confirmed [31]; Demonstrated [123]).

### The September IE zero-day and Ke3chang

Microsoft published Security Advisory 2887505 on 17 September for CVE-2013-3893, a remote code execution flaw in Internet Explorer 6 to 11, and US-CERT said Microsoft was aware of targeted attacks against IE8 and IE9 and that a Fix it shim prevents exploitation (Confirmed [30][29]). MS13-080 closed it on 8 October and lists CVE-2013-3897 as under targeted attack too (Confirmed [81]). The FireEye "Operation DeputyDog" post could not be opened; ATT&CK's G0025 APT17 lists the alias Deputy Dog but cites only a 2015 report, so no 2013 technique is bound to it (Demonstrated [123]).

ATT&CK's G0004 Ke3chang is "attributed to actors operating out of China", and 19 of its technique entries cite Villeneuve et al. (2014), Operation Ke3chang, on attacks against ministries of foreign affairs (Confirmed [48]). The report itself returned an error, so dating that activity to 2013 is this study's inference, and its techniques are recorded as context, not bound (Inferred [48]).

## Part 3: the wider state and espionage record

### Russia-linked reporting

Kaspersky's Red October report describes a five-year espionage campaign run through more than 60 command-and-control domains (Confirmed [1]). Kaspersky "strongly believe[s]" the attackers are Russian-speaking, but says "there is no evidence linking this with a nation-state sponsored attack", and no ATT&CK object records Red October (Confirmed that Kaspersky says so [1]; Demonstrated [123]).

Kaspersky and CrySyS analysed MiniDuke on 27 February: PDFs themed on an ASEM human-rights seminar and on Ukraine's NATO plans carried the Adobe Reader zero-day CVE-2013-0640, and the backdoor found its command server through Twitter and then Google Search and received payloads inside GIF files (Confirmed as the vendors' findings [52]). They counted 59 victims in 23 countries and named no state in 2013 (Confirmed [52]). ATT&CK records MiniDuke as S0051, used by G0016 APT29, which ATT&CK attributes to the SVR on the strength of April 2021 US and UK statements; its entries citing the February 2013 report are T1008 Fallback Channels, T1105 Ingress Tool Transfer and T1102.001 Dead Drop Resolver (Confirmed [53]).

ATT&CK's C0023 Operation Ghost, an APT29 campaign against European foreign ministries and an EU embassy in Washington, was first seen in September 2013 and last seen in October 2019 (Confirmed [54]). ESET wrote in 2019 that "We believe Operation Ghost started in 2013", based on PolyglotDuke's first known compilation, and noted that Turla and Sednit were present on some of the same machines and that it could not rule out a false flag (Confirmed [55]). ATT&CK's G0047 Gamaredon Group, a "suspected Russian" espionage group, has targeted Ukrainian military, law enforcement, judiciary and NGOs since at least 2013 (Demonstrated [56]). The home for both groups is [Russia-attributed threat actors](/case-studies/THREAT_ACTORS_RUSSIA.md) (Confirmed that the home study carries Gamaredon [127]).

### North Korea-linked reporting (summary)

The home for these is [North Korea-attributed threat actors](/case-studies/THREAT_ACTORS_NORTH_KOREA.md), which records Kaspersky's first naming of Kimsuky in 2013 (Confirmed that the home study carries it [127]).

On 19 December 2014 the FBI said tools used against Sony Pictures resembled those of a March 2013 attack on South Korean banks and media outlets, which the FBI said North Korea carried out (Confirmed [49]). ATT&CK's G0032 Lazarus Group description says its malware correlates to Operation Troy and DarkSeoul, citing Novetta's Operation Blockbuster, but no Lazarus technique entry cites a 2013 report (Confirmed [15]). The library's copy of ATT&CK describes S0041 Wiper as destructive malware used in the March 2013 breaches of South Korean banks and media companies, with one technique, T1072 Software Deployment Tools (Demonstrated [123]). No 2013 primary was opened for the day or impact of the attack.

Kaspersky's Kimsuky report of 11 September, titled as a question, covers 11 targets in South Korea and two in China, including the Sejong Institute, KIDA, the Ministry of Unification and Hyundai Merchant Marine (Confirmed as Kaspersky's findings [50]). The tooling included a keylogger, an HWP document stealer, a modified TeamViewer and e-mail command and control through a Bulgarian webmail service, and it disabled firewalls (Confirmed [50]). North Korean basing is called only "the likely theory" (Confirmed that Kaspersky says so [50]). ATT&CK's G0094 Kimsuky has 16 technique entries citing that report, three of them v20.0 ids (T1686, T1685, T1680) (Confirmed [51]; Demonstrated [123]).

### Iran-linked reporting (summary)

The home is [Iran-attributed threat actors](/case-studies/THREAT_ACTORS_IRAN.md), and the [2016 chronicle](/case-studies/CHRONICLE_2016.md) records the indictment (Confirmed that the home studies carry them [127]). The FBI says that on 21 January 2016 a Southern District of New York grand jury indicted seven Iranian nationals, employees of ITSecTeam and Mersad, companies that performed work for the Iranian Government including the IRGC, for a coordinated DDoS campaign against the US financial sector from 2011 through 2013 (Confirmed as charged [27]). One of them, Hamid Firoozi, is also charged with an intrusion into the SCADA systems of the Bowman Avenue Dam in Rye, New York, during late 2013 (Confirmed as charged [28]). ATT&CK records G0064 APT33 ("suspected Iranian"), G0052 CopyKittens (Iranian) and G0122 Silent Librarian (members affiliated with the Mabna Institute acting for the IRGC) as operating since at least 2013 (Demonstrated [58]).

### Other states and surveillance vendors

ATT&CK's G0021 Molerats is "Arabic-speaking, politically-motivated" with no state named, and its T1553.002 Code Signing entry, for forged Microsoft certificates, cites FireEye's Operation Molerats report of 23 August 2013 (Confirmed [57]). The FireEye post itself could not be opened. An FBI wanted notice alleges that the Syrian Electronic Army hacks in support of the Syrian regime and carried out dozens of attacks on US government agencies, media and private organizations from September 2011 to January 2014, charged by complaint in the Eastern District of Virginia on 12 June 2014 (Confirmed as alleged [59]).

Citizen Lab found FinSpy command servers, part of Gamma International's FinFisher, in 25 countries in March, with an Ethiopian campaign using images of the opposition group Ginbot 7 as bait, and in 36 countries in April, with a Malay-language sample themed on Malaysia's 2013 election that masqueraded as Mozilla Firefox (Confirmed as Citizen Lab's findings [64][65]). ATT&CK records FinFisher as S0182; its 2013 citations were not checked (Demonstrated [123]). The home for FinFisher is [Other states' threat actors](/case-studies/THREAT_ACTORS_OTHER_STATES.md), and [The Zero-Day Market](/case-studies/ZERO_DAY_MARKET_EVENTS.md) covers the wider exploit and surveillance-tool market (Confirmed that the home study covers that market [127]).

### The Snowden documents (summary)

The homes are [The Hacker and the State](/case-studies/HACKER_AND_THE_STATE_CASES.md) and [United States-attributed threat actors](/case-studies/THREAT_ACTORS_UNITED_STATES.md) (Confirmed that the home studies carry the 2013 reports [127]). The Guardian published on 6 June a top-secret FISA Court order, granted on 25 April and running to 19 July, requiring Verizon to hand over call metadata in bulk, and the PRISM presentation claiming "collection directly from the servers" of major US providers; every company that responded denied knowledge of the program (Reported [60][61]). Der Spiegel reported on 20 September that Snowden documents indicate GCHQ was behind the Belgacom intrusion, "Operation Socialist", which used Quantum Insert against Belgacom employees with access since 2010, and on 29 December described NSA's Tailored Access Operations and the QUANTUM tools, including use against OPEC staff in Vienna (Reported [62][63]). No ATT&CK technique is bound to these press accounts (Inferred).

### Groups ATT&CK dates to 2013

ATT&CK records the Carbanak group (G0008) as targeting financial institutions since at least 2013 (Confirmed [42]). With Gamaredon, APT33, CopyKittens and Silent Librarian, it is recorded as context, since no 2013 event was opened for any of them (Confirmed [42]; Demonstrated [56][58]).

## Part 4: denial of service

### Spamhaus

Cloudflare wrote on 20 March that Spamhaus asked for its help on Tuesday 19 March during a large DDoS, and that DNS reflection was the largest source, about 75 Gbps (Confirmed as Cloudflare's account [12]). Its 27 March post says Spamhaus contacted it on Monday 18 March about an attack of about 10 Gbps, largely from open DNS recursors, which peaked near 90 Gbps on 19 March and at 120 Gbps on 22 March at Cloudflare's network, after which attackers targeted Cloudflare's upstream bandwidth providers (Confirmed for Cloudflare's measurements [13]; Reported for the 10 Gbps starting figure [13]). The post relays that one Tier 1 provider saw more than 300 Gbps of attack traffic related to Spamhaus and that several Tier 1 networks, mostly in Europe, became congested (Reported [13]).

US-CERT's TA13-088A of 29 March explains the mechanism: open DNS servers plus spoofed source addresses flood a target with responses (Confirmed [14]). That is T1498.002 Reflection Amplification, which the library pairs with CAPEC-490 Amplification (Inferred for the binding; Demonstrated [123][124]).

### The bank campaign (summary)

The 2011 to 2013 campaign against US banks is recorded in Part 3 and in its home study; T1498 Network Denial of Service is assigned from the FBI's description (Confirmed as charged [27]; Inferred for the binding).

## Part 5: breaches and data loss

### Target (summary)

The home is [E-Commerce Threats](/case-studies/ECOMMERCE_THREATS.md), which records Target's card and personal-data figures from the Senate staff report (Confirmed that the home study carries them [127]). Target confirmed on 19 December unauthorized access to payment card data: about 40 million credit and debit card accounts may have been affected for cards used between 27 November and 15 December, and a third-party forensics firm was engaged (Confirmed [122]). The Senate Commerce Committee's majority staff report of 26 March 2014 gives the window as 27 November to 18 December, says data on as many as 110 million customers was taken, and records that the Department of Justice told Target of the breach on 12 December and that on 10 January 2014 Target disclosed personal data for up to 70 million customers (Confirmed [40]). KrebsOnSecurity first reported the investigation on 18 December (Reported [88]).

The report says it relies on media reports and expert analyses for how the attackers got in: through network access given to a small Pennsylvania HVAC vendor, reportedly using credentials stolen from Fazio Mechanical, with point-of-sale malware, multiple automated anti-intrusion alerts that Target did not respond to, sensitive assets not isolated, and data moved to a server in Eastern Europe (Reported [40]). T1199 Trusted Relationship and T1078 Valid Accounts are assigned from that account and score as Reported (Inferred for the binding).

### Adobe

Adobe's chief security officer, Brad Arkin, wrote on 3 October that attackers accessed Adobe customer IDs and encrypted passwords and removed information on about 2.9 million customers, including names, encrypted card numbers, expiration dates and order data; Adobe did not believe decrypted card numbers were taken (Confirmed [32]). Adobe was also investigating illegal access to the source code of numerous products, believed to be related, and its security team had discovered the attacks very recently (Confirmed [32]). US-CERT's alert the same day put the figure at up to 3 million customers and said source code for multiple products may also have been compromised (Confirmed [33]). Neither describes the method, and no technique is bound (Inferred).

### Yahoo (summary)

The homes are the [2016 chronicle](/case-studies/CHRONICLE_2016.md) and the [2017 chronicle](/case-studies/CHRONICLE_2017.md) (Confirmed that the home studies carry the disclosures [127]). Yahoo's 8-K exhibit of 14 December 2016 says an unauthorized party stole data tied to more than one billion user accounts in August 2013: names, e-mail addresses, phone numbers, dates of birth, MD5-hashed passwords and some security questions and answers; the intrusion itself was not identified (Confirmed [89]). Verizon's 8-K exhibit of 3 October 2017 says Yahoo, then part of Oath, believed all Yahoo user accounts were affected, and Yahoo's help page says all accounts existing at the time were likely affected and that payment card and bank data were not included (Confirmed [92][26]).

### Department of Energy

The DOE Inspector General's report IG-0900, a memo dated 6 December, says that in July 2013 attackers exploited a software vulnerability in the Management Information System and exfiltrated personally identifiable information on more than 104,000 people from the DOEInfo repository: Social Security numbers, birth data, some bank account numbers and security questions and answers (Confirmed [25]). The system had direct internet access without adequate controls, there were earlier MIS incidents in May 2011 and January 2012, core support for the application had ended in July 2012, and about USD 1.6 million was estimated, as of October, for credit monitoring and call-center labor (Confirmed [25]). T1190 Exploit Public-Facing Application is assigned from the report's description (Inferred for the binding).

### The Drinkman indictment

The US Attorney for New Jersey made public on 25 July a second superseding indictment charging Vladimir Drinkman, Aleksandr Kalinin, Roman Kotov, Mikhail Rytikov and Dmitriy Smilianets in what it called the largest hacking and data breach scheme prosecuted in the United States: more than 160 million card numbers (Confirmed as charged [68]). Named victims include NASDAQ, 7-Eleven, Carrefour, JCP, Hannaford, Heartland, Wet Seal, Commidea, Dexia, JetBlue, Dow Jones, Euronet, Visa Jordan, Global Payment, Diners Singapore and Ingenicard (Confirmed as charged [68]). As alleged, initial entry was often SQL injection, followed by malware that created back doors and sniffers, with access regained after remediation, and the data was sold as dumps; Drinkman and Smilianets were arrested in the Netherlands on 28 June 2012 and three defendants remained at large (Confirmed as charged [68]). T1190, T1040 Network Sniffing and T1005 Data from Local System are assigned from that description, and CAPEC-66 SQL Injection is paired with it; the release names no CVE or CWE (Inferred [68]).

### The AT&T iPad case

Andrew Auernheimer was sentenced on 18 March to 41 months for the AT&T server breach that took e-mail addresses of about 120,000 iPad 3G users, which were disclosed to Gawker; he had been convicted on 20 November 2012 (Confirmed [94]). The later appellate history was not checked.

## Part 6: the vulnerability record

### Exploited in 2013 or catalogued in KEV

| CVE | Product and flaw | Exploitation record | Fix | CWE (source) | KEV added | Sources |
|---|---|---|---|---|---|---|
| CVE-2013-0422 | Oracle Java 7 Security Manager bypass | Actively exploited, public exploit code (US-CERT, 10 Jan); Blackhole and Nuclear Pack (NVD); Fiesta kit (May); Icefog | Java 7 Update 11 | CWE-284 (NVD) | 2022-05-25, known ransomware use | [2][3][69][70][21][31] |
| CVE-2013-0625 | Adobe ColdFusion 9.x authentication bypass | Exploited in the wild, January | Not checked | CWE-287 (NVD) | 2022-03-07, with CVE-2013-0629 and -0631; -0632 on 2022-03-03 | [72] |
| CVE-2013-0640, CVE-2013-0641 | Adobe Reader and Acrobat 9.x to 11.x memory corruption | Exploited in the wild; MiniDuke's PDFs (0640) | Not checked | CWE-787 (NVD, KEV); CWE-120 (KEV, 0641) | 2022-03-03 | [73][52][4] |
| CVE-2013-2551 | Internet Explorer 6 to 10 use-after-free | Demonstrated by VUPEN at Pwn2Own | Not checked | CWE-416 (NVD) | 2022-03-28, known ransomware use | [74] |
| CVE-2013-1347 | Internet Explorer 8 use-after-free in CGenericElement | Exploited in the wild, May (NVD, CERT/CC); Microsoft aware of attacks through IE8 | Advisory 2847140 (3 May); MS13-038 (14 May) | CWE-416 (NVD) | 2022-03-03 | [18][19][20][75][76] |
| CVE-2013-2094 | Linux kernel before 3.8.9, perf_swevent_init local privilege escalation | Not stated in the record opened | Linux 3.8.9 | CWE-189 (NVD, a category not in the library's data) | 2022-09-15 | [77] |
| CVE-2013-2465 | Oracle Java SE 7u21, 6u45, 5.0u45 and earlier | Not stated in the record opened | Not checked | CWE-693 (NVD) | 2022-03-28, known ransomware use | [78] |
| CVE-2013-2251 | Apache Struts 2.0.0 to 2.3.15, prefixed-parameter remote command execution (S2-016) | Not stated in the record opened | Struts 2.3.15.1 | CWE-74 (NVD) | 2022-03-25 | [79][4][131] |
| CVE-2013-3893 | Internet Explorer 6 to 11 remote code execution | Targeted attacks against IE8 and IE9 | Fix it shim; MS13-080 (8 Oct) | CWE-416 (NVD); CWE-399 (KEV) | 2025-08-12 | [29][30][81][4][128] |
| CVE-2013-3897 | Internet Explorer | Under targeted attack (MS13-080) | MS13-080 (8 Oct) | Not checked | 2022-03-03 | [81][4] |
| CVE-2013-3906 | Microsoft Graphics Component TIFF handling (Windows, Office, Lync) | Targeted attacks against Office (MS13-096) | Advisory 2896666 (5 Nov); MS13-096 (10 Dec) | CWE-94 (NVD) | 2022-02-15 | [36][4][129] |
| CVE-2013-3918 | InformationCardSigninHelper ActiveX control (icardie.dll), Windows XP to 8.1 | Exploited in the wild, November (NVD) | November bulletins (12 Nov; match Inferred, bulletin not opened) | CWE-787 (NVD) | 2025-10-06 | [38][37] |
| CVE-2013-5065 | Windows XP and Server 2003 NDProxy.sys privilege escalation | Exploited in the wild, November (NVD); limited targeted attacks | Advisory 2914486 workaround (alert 28 Nov); MS14-002 (14 Jan 2014) | NVD-CWE-noinfo (NVD; no CWE assigned) | 2022-03-03 | [39][85][4][133] |
| CVE-2013-3900 | WinVerifyTrust Authenticode signature verification | Microsoft aware of targeted attacks | MS13-098 (10 Dec) | CWE-347 (NVD) | 2022-01-10 | [86][4][130] |

The November watering hole that US-CERT described, on a US website specializing in domestic and international security policy, was patched in the November bulletins; the CISA alert does not name the CVE, and the match with CVE-2013-3918, which NVD says was exploited in the wild that month, is this study's inference (Confirmed [37][38]; Inferred). CVE-2013-3918 is also in the Equation exploit list carried by [United States-attributed threat actors](/case-studies/THREAT_ACTORS_UNITED_STATES.md) (Confirmed that the home study carries it [127]). The watering-hole victim site of May 2013 is not named in the primaries opened (Confirmed [18][20]).

### The year's Java problem

US-CERT's TA13-010A said all Java 7 versions through Update 10 were affected, that browsers using the Java 7 plug-in were at high risk because users could be enticed to a site hosting a malicious applet, and advised disabling Java in browsers and updating to Java 7 Update 11, which sets the default security level to High (Confirmed [2]). Oracle's Security Alert fixed CVE-2013-0422 and a second browser-Java flaw and cites reported in-the-wild exploitation; the alert's date was not printed in the text extracted, so it is not checked (Confirmed [69]). CERT/CC's VU#625617 was released the same day and revised on 12 June (Confirmed [70]). Two 2013 Java flaws, CVE-2013-0422 and CVE-2013-2465, carry KEV's known-ransomware-use flag, which records use by ransomware campaigns at some point, not necessarily in 2013 (Confirmed [4]).

### Drive-by on news sites

US-CERT's TA13-141A says that on 16 May the federalnewsradio.com and wtop.com websites were found compromised to redirect Internet Explorer users to the Fiesta exploit kit, which used CVE-2009-0927, CVE-2010-0188 and CVE-2013-0422 to deliver a ZeroAccess variant, and that no malicious code remained by 17 May (Confirmed [21]). That is T1189 Drive-by Compromise followed by T1203 Exploitation for Client Execution (Inferred for the binding).

### Disclosures without reported exploitation

US-CERT's TA13-193A of 12 July warns that a public exploit tool targets two flaws in McAfee ePolicy Orchestrator 4.6.5 and earlier from the local network and can add rogue systems, steal cached domain credentials and execute commands on the ePO server and managed systems (Confirmed [24]). TA13-207A of 26 July says internet-exposed IPMI gives low-level access that can override operating-system controls and should be restricted to management addresses; NVD's CVE-2013-4786 records the IPMI 2.0 RAKP hash disclosure under CWE-255, a category not in the library's data (Confirmed [80][134]; Demonstrated [124]). On 18 October US-CERT reported a backdoor in firmware for various D-Link routers that lets unauthenticated remote users bypass password authentication on the remote management web server (VU#248083) (Confirmed [34]). KEV separately lists CVE-2013-5223 for the D-Link DSL-2760U (Confirmed [4]). Rails fixed CVE-2013-0155 and CVE-2013-0156, which it called extremely critical; NVD lists CVE-2013-0156 under CWE-20 (Confirmed [71][132]). None of these is bound to a technique, since the record opened describes no exploitation (Inferred).

### TLS

Royal Holloway's Lucky Thirteen, published on 4 February, lets a man-in-the-middle recover plaintext from TLS and DTLS connections that use CBC-mode encryption; the flaw is in the specification, not one implementation, and patches were coordinated (Confirmed [117]). NVD lists it as CVE-2013-0169 under CWE-310, a category that is not in the library's CWE data and is not bound (Confirmed [118]; Demonstrated [124]). Royal Holloway's "On the Security of RC4 in TLS and WPA" followed on 13 March, and NVD lists CVE-2013-2566 for the RC4 single-byte biases under CWE-326 and CWE-327 (Confirmed [119][120]).

### Microsoft's year in bulletins

Microsoft's 2013 bulletins run from MS13-001 on 8 January to MS13-106 on 10 December; MS13-107 returns an error, which gives 106 bulletins by numbering (Confirmed [87]; count Inferred).

### The KEV tail

CISA's catalog 2026.11.10 holds 38 CVE-2013 entries, six flagged with known ransomware use: CVE-2013-0074, CVE-2013-0422, CVE-2013-0431, CVE-2013-2465, CVE-2013-2551 and CVE-2013-3993 (Confirmed [4]). Most were added in 2022; CVE-2013-3893 was added on 12 August 2025 and CVE-2013-3918 on 6 October 2025, twelve years after exploitation (Confirmed [4]). KEV did not exist in 2013, and its dates record when CISA catalogued a flaw, not when it was first exploited (Inferred).

## Part 7: crimeware, takedowns and the courts

### Citadel

Microsoft announced on 5 June that, with FS-ISAC, NACHA, the American Bankers Association, Agari and the FBI, it had disrupted more than a thousand Citadel botnets; an order from the US District Court for the Western District of North Carolina let it cut off communication with 1,462 of them (Confirmed [23]). Its blog calls the action Operation b54, its seventh botnet operation, says the FBI took separate steps, and records that Citadel blocked victims' access to anti-malware sites (Confirmed [104]). Citadel keylogged online banking credentials, which is T1056.001 Keylogging (Confirmed [23]; Inferred for the binding). Microsoft's estimates that Citadel caused more than half a billion dollars in losses and affected upwards of five million people are its own (Reported [23]). The FBI says Reveton ransomware was delivered by Citadel (Confirmed [84]). The library's ATT&CK data has no Citadel object (Demonstrated [123]).

### ZeroAccess

On 5 December Microsoft's Digital Crimes Unit, Europol's EC3, the FBI and industry partners including A10 Networks disrupted the Sirefef, or ZeroAccess, peer-to-peer botnet, which Microsoft says infected more than 2 million computers for search hijacking and click fraud and cost advertisers an estimated USD 2.7 million a month (Confirmed [41]). It was Microsoft's eighth botnet operation in three years and the first since its Cybercrime Center opened on 14 November (Confirmed [41]). ATT&CK records Zeroaccess as S0027, a kernel-mode rootkit that adds victims to the botnet, mapped to T1014 Rootkit and T1564.004 NTFS File Attributes (Confirmed [90]).

### Ransomware: from lock screens to encryption

US-CERT warned on 21 March of DHS-themed ransomware that tells victims their computer is suspended and demands a fine to unlock it; one variant takes a webcam photo of the victim (Confirmed [11]). US-CERT's TA13-309A of 5 November describes CryptoLocker, which surfaced in 2013 and spreads mainly through phishing e-mails with malicious attachments posing as businesses and as FedEx and UPS tracking notices, and sometimes follows earlier botnet infections (Confirmed [35]). It encrypts files on local, mapped network, USB and some cloud-synced drives with asymmetric encryption, keeps the private key on its command server, and gives victims three days to pay by MoneyPak or Bitcoin (Confirmed [35]). Its recommended mitigations are offline backups, current antivirus, patching, caution with links and attachments, and reporting to IC3 (Confirmed [35]). CryptoLocker has no ATT&CK software object, so it binds by technique only: T1566.001, T1204.002 and T1486 (Confirmed [35]; Demonstrated [123]; Inferred for the binding).

The FBI says that on 2 June 2014 US and foreign authorities seized CryptoLocker's command servers alongside the GameOver Zeus disruption, and that court documents name Evgeniy Bogachev as the leader of the gang behind both; the 2014 record is the home for that action (Confirmed [82]). The FBI's wanted notice says it began investigating GameOver Zeus in September 2011, believes it responsible for more than 1 million infections and more than USD 100 million in losses, and records Bogachev's indictment in Nebraska on 22 August 2012 as "lucky12345" (Confirmed [83]). ATT&CK records P2P ZeuS, also called Gameover ZeuS, as S0016 (Confirmed [91]). The [Ransomware ecosystem](/case-studies/RANSOMWARE_ECOSYSTEM.md) study covers the later ransomware economy.

### WordPress brute force

US-CERT warned on 15 April of a campaign brute-forcing WordPress admin panels using accounts named "admin" and weak passwords (Confirmed [17]). The alert relays press figures of more than 90,000 servers and 60 million requests blocked by Cloudflare in one hour (Reported [17]). That is T1110.001 Password Guessing (Inferred for the binding).

### Liberty Reserve

Treasury named Liberty Reserve S.A., registered in Costa Rica and operating since 2001, a primary money laundering concern under Section 311 of the USA PATRIOT Act, the first such use against a virtual currency provider, in coordination with the Southern District of New York (Confirmed [22]). The indictment unsealed on 28 May charges Liberty Reserve and seven principals and employees with money laundering and unlicensed money transmission: more than one million users, 200,000 of them in the United States, about 55 million transactions and more than USD 6 billion laundered (Confirmed as charged [66]). Five defendants were arrested on 24 May, founder Budovsky in Spain; five domains were seized, 45 bank accounts restrained or seized and a civil action filed against 35 exchanger sites, with action in 17 countries, which the Justice Department said was believed to be the largest international money laundering prosecution in history (Confirmed [66]).

### Silk Road

The Southern District of New York filed a civil forfeiture action against Silk Road on 30 September and seized the site; Ross William Ulbricht, alleged to be "Dread Pirate Roberts", was arrested in San Francisco on 1 October on a complaint charging narcotics, computer hacking and money laundering conspiracies, with a separate indictment in Baltimore (Confirmed as charged [67]). On 25 October a further 144,336 bitcoins were seized, about 173,991 in all, worth over USD 33.6 million that day and described as the largest bitcoin seizure ever (Confirmed [67]). The February 2014 indictment release alleges that he created Silk Road on Tor around January 2011 and ran it until law enforcement shut it down in October 2013 (Confirmed as charged [93]). The later trial outcome was not checked.

## Part 8: industrial systems

ICS-CERT's Monitor for October to December 2013 says ICS-CERT responded to 256 incidents in 2013, 151 (59 percent) in energy and 50 (20 percent) in critical manufacturing (Confirmed [95]). Of these, 79 were confirmed or suspected compromises, 57 were not compromised and 120 were indeterminate, often because logs were inadequate (Confirmed [95]). Initial vectors included unauthorized access to internet-facing devices, scanning, removable media, vulnerability exploitation, spear-phishing, SQL injection and externally facing web services; more than 50 organizations were notified about watering holes, and an emerging actor's campaign hit 40 critical infrastructure organizations, mostly in energy (Confirmed [95]). The same Monitor lists the late-2013 DNP3 improper-input-validation advisories: ICSA-13-291-01A DNP3 Implementation Vulnerability (21 November), the Catapult DNP3 driver and GE Proficy DNP3 (19 November), Cooper Power Systems Cybectec DNP3 Master OPC Server (12 December) and NovaTech Orion DNP3 (18 December) (Confirmed [95]).

The Bowman Avenue Dam intrusion of late 2013 is recorded in Part 3 as charged; no ATT&CK for ICS mapping is recorded for it (Confirmed [28]). The [ICS attacks and advisories](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md) study covers the later industrial record.

## Part 9: law, policy and standards

### The executive order and the framework

Executive Order 13636, "Improving Critical Infrastructure Cybersecurity", was signed on 12 February and published at 78 FR 11739 on 19 February (Confirmed [6]). It orders unclassified threat reports to targeted entities, expands Enhanced Cybersecurity Services to all critical infrastructure sectors, has NIST lead a framework (preliminary in 240 days, final in one year), sets up a DHS voluntary program, has DHS identify critical infrastructure where an incident could have catastrophic effects (Section 9) and adds privacy protections based on the Fair Information Practice Principles (Confirmed [96]). PPD-21, issued the same day, designates 16 critical infrastructure sectors, each with a sector-specific agency, and revokes HSPD-7 of 17 December 2003, while plans made under HSPD-7 stay in effect until revoked or superseded (Confirmed [7]). NIST's history records the RFI of 26 February (270 or more responses), five workshops (3 April; 29 to 31 May; 10 to 12 July; 11 to 13 September; 14 to 15 November), a preliminary draft released on 1 July (NIST's wording), a discussion draft on 28 August and a request for comments on the Preliminary Framework on 29 October (200 or more comments) (Confirmed [97]). Framework 1.0 followed on 12 February 2014 (Confirmed [8][105]).

### Other US rules and guidance

HHS's HIPAA Omnibus final rule (78 FR 5566, 25 January; effective 26 March; compliance by 23 September) implements HITECH and GINA, makes business associates directly liable for certain Privacy and Security Rule requirements, adopts tiered civil money penalties and replaces the Breach Notification Rule's harm threshold with a more objective standard (Confirmed [99]). NIST published SP 800-53 Rev. 4 in April (updated 22 January 2015, withdrawn 23 September 2021 after Rev. 5), SP 800-40 Rev. 3 on enterprise patch management in July (withdrawn 6 April 2022), SP 800-83 Rev. 1 on malware incident prevention and handling in July, which calls malware the most common external threat to most hosts, FIPS 186-4 in July (withdrawn 3 February 2024) and SP 800-63-2, the electronic authentication guideline with four levels of assurance, in August (withdrawn 22 June 2017) (Confirmed [98][106][107][109][108]).

### Europe and the United Nations

The European Commission announced on 9 January that the European Cybercrime Centre would open at Europol in The Hague on 11 January (Confirmed [100]). On 7 February it published the EU cybersecurity strategy "An Open, Safe and Secure Cyberspace", with five priorities and a proposed Network and Information Security directive covering key internet enablers and critical infrastructure operators in energy, transport, banking and healthcare (Confirmed [101]). The UN Group of Governmental Experts from fifteen States reported on 24 June (A/68/98) that international law, in particular the UN Charter, applies to the ICT environment, that State sovereignty applies to ICT activities and infrastructure, and that States must not use proxies to commit internationally wrongful acts (Confirmed [102]). CCDCOE records that the original Tallinn Manual, on cyber operations at the level of use of force, self-defence and armed conflict, was published in 2013 by Cambridge University Press (Confirmed [103]).

### Standards and catalogs

ISO/IEC 27002:2013, the code of practice for information security controls, was published in October as edition 2, replacing the 2005 edition; ISO lists 27001:2013 as the predecessor of 27001:2022, but its 2013 publication month was not checked (Confirmed [110]). The CVE Editorial Board's first vote on a new ID syntax, in April, tied between two of three options; a second vote in May decided it, a September news item announced the change for 1 January 2014, the first IDs with variable-length sequence numbers were issued on 13 January 2015, and from 9 December the CVE List was also published in ICASI's CVRF XML format (Confirmed [111][112]). CWE 2.4 (21 February) modified 96 entries and added 11, and CWE 2.5 (17 July) added 20, mainly for mobile applications and the OWASP Top Ten 2013 (Confirmed [113]). CAPEC 2.0 (8 April) changed only the schema namespace, followed by 2.1 (21 June) and 2.2 (18 December) (Confirmed [114]). RFC 6962, Certificate Transparency, by Laurie, Langley and Kasper of Google, was published in June with Experimental status and has since been obsoleted by RFC 9162 (Confirmed [115]). On 19 June Microsoft announced a standing Mitigation Bypass Bounty of up to USD 100,000 for novel exploitation techniques against Windows 8.1 Preview protections, a BlueHat Bonus of up to USD 50,000 for defensive ideas accompanying a qualifying bypass, and a 30-day IE11 Preview bug bounty of up to USD 11,000 (Confirmed [116]).

## Part 10: the defender view

**Plug-ins needed removing, not only patching.** US-CERT advised disabling Java in browsers, and Java and IE flaws of 2013 carry KEV's known-ransomware flag (Confirmed [2][4]). [Process Segment Execution Prevention](/mitre/d3fend/process-segment-execution-prevention.md), [Segment Address Offset Randomization](/mitre/d3fend/segment-address-offset-randomization.md), [URL Reputation Analysis](/mitre/d3fend/url-reputation-analysis.md) and [URL Analysis](/mitre/d3fend/url-analysis.md) are the library's D3FEND links for T1189, and [Executable Allowlisting](/mitre/d3fend/executable-allowlisting.md) fits too (Demonstrated [123]; Inferred for the pairing). [M1042 Disable or Remove Feature or Program](/mitre/mitigations/M1042.md), [M1021 Restrict Web-Based Content](/mitre/mitigations/M1021.md), [M1048 Application Isolation and Sandboxing](/mitre/mitigations/M1048.md) and [M1050 Exploit Protection](/mitre/mitigations/M1050.md) are the ATT&CK mitigations (Inferred).

**Interim workarounds bought weeks.** Microsoft's Fix it shim for CVE-2013-3893 came three weeks before MS13-080, and Advisory 2847140 came 11 days before MS13-038, though US-CERT noted that the earlier workaround did not correct the flaw (Confirmed [29][81][18][75][19]). [Software Update](/mitre/d3fend/software-update.md) and [M1051 Update Software](/mitre/mitigations/M1051.md) cover the fix itself (Inferred). SP 800-40 Rev. 3 gave the year its federal patch-management guidance (Confirmed [106]).

**Reflection needed closing at the source.** The Spamhaus attack used open DNS resolvers, and TA13-088A is the remedy (Confirmed [12][14]). The library links [Inbound Traffic Filtering](/mitre/d3fend/inbound-traffic-filtering.md), [Inbound Session Volume Analysis](/mitre/d3fend/inbound-session-volume-analysis.md) and [Network Traffic Filtering](/mitre/d3fend/network-traffic-filtering.md) to T1498.002 (Demonstrated [123]); [M1037 Filter Network Traffic](/mitre/mitigations/M1037.md) is the ATT&CK mitigation (Inferred).

**Encryption ransomware needed backups out of reach.** CryptoLocker encrypted mapped shares and some cloud-synced folders, and US-CERT put offline backups first (Confirmed [35]). The library links [Restore File](/mitre/d3fend/restore-file.md), [File Integrity Monitoring](/mitre/d3fend/file-integrity-monitoring.md) and [Decoy File](/mitre/d3fend/decoy-file.md) to T1486, and [Email Filtering](/mitre/d3fend/email-filtering.md), [File Analysis](/mitre/d3fend/file-analysis.md) and [Dynamic Analysis](/mitre/d3fend/dynamic-analysis.md) to T1566.001 (Demonstrated [123]); [M1053 Data Backup](/mitre/mitigations/M1053.md) and [M1017 User Training](/mitre/mitigations/M1017.md) are the ATT&CK mitigations (Inferred).

**Vendor access needed its own boundary.** Target's attackers reportedly came through an HVAC vendor, and the Senate report says sensitive assets were not isolated (Reported [40]). The library links [Remote Terminal Session Detection](/mitre/d3fend/remote-terminal-session-detection.md), [Connection Attempt Analysis](/mitre/d3fend/connection-attempt-analysis.md) and [Session Termination](/mitre/d3fend/session-termination.md) to T1199, and [Account Locking](/mitre/d3fend/account-locking.md) and [User Account Permissions](/mitre/d3fend/user-account-permissions.md) to T1078 (Demonstrated [123]); [M1030 Network Segmentation](/mitre/mitigations/M1030.md) and [M1032 Multi-factor Authentication](/mitre/mitigations/M1032.md) are the ATT&CK mitigations (Inferred).

**Credentials needed hardening.** APT1 dumped LSASS memory and passed the hash, Citadel and Kimsuky keylogged, and the WordPress campaign guessed "admin" passwords (Confirmed [10][23][51][17]). The library links [Strong Password Policy](/mitre/d3fend/strong-password-policy.md), [Credential Hardening](/mitre/d3fend/credential-hardening.md), [Multi-factor Authentication](/mitre/d3fend/multi-factor-authentication.md) and [Change Default Password](/mitre/d3fend/change-default-password.md) to T1110.001, [Process Spawn Analysis](/mitre/d3fend/process-spawn-analysis.md) and [Kernel-based Process Isolation](/mitre/d3fend/kernel-based-process-isolation.md) to T1003.001, and [Input Device Analysis](/mitre/d3fend/input-device-analysis.md) to T1056.001; it links nothing to T1550.002 (Demonstrated [123]). SP 800-63-2 set the federal authentication levels that year (Confirmed [108]). [M1027 Password Policies](/mitre/mitigations/M1027.md) and [M1026 Privileged Account Management](/mitre/mitigations/M1026.md) are the ATT&CK mitigations (Inferred).

**Internet-facing and management systems needed taking off the internet.** The DOE system had direct internet access, IPMI and ePO exposed management functions, and ICS-CERT counted unauthorized access to internet-facing devices among its vectors (Confirmed [25][80][24][95]). The library links [Inbound Traffic Filtering](/mitre/d3fend/inbound-traffic-filtering.md), [Database Query String Analysis](/mitre/d3fend/database-query-string-analysis.md) and [Client-server Payload Profiling](/mitre/d3fend/client-server-payload-profiling.md) to T1190 (Demonstrated [123]); [M1035 Limit Access to Resource Over Network](/mitre/mitigations/M1035.md) and [M1030 Network Segmentation](/mitre/mitigations/M1030.md) are the ATT&CK mitigations (Inferred).

**Software supply needed integrity checks.** Winnti's trojan came from a game publisher's update server, and the group stole code-signing certificates (Confirmed [16]). The library links [Software Inventory](/mitre/d3fend/software-inventory.md), [Software Update](/mitre/d3fend/software-update.md) and [Restore Software](/mitre/d3fend/restore-software.md) to T1195.002 and nothing to T1553.002 (Demonstrated [123]). Certificate Transparency, published in June, is the protocol answer for mis-issued certificates, and [Certificate Pinning](/mitre/d3fend/certificate-pinning.md) and [Message Encryption](/mitre/d3fend/message-encryption.md) are the library's D3FEND pages that fit the year's TLS weaknesses (Confirmed [115][117][119]; Inferred for the pairing).

**Logging decided whether an incident could be classified.** ICS-CERT could not determine 120 of 256 incidents, often for lack of logs (Confirmed [95]). [M1047 Audit](/mitre/mitigations/M1047.md) is the ATT&CK mitigation, and the [incident response reference](/INCIDENT_RESPONSE_REFERENCE.md) covers the process side (Inferred).

## Part 11: MITRE mappings

No 2013 record opened here carries an ATT&CK id; every binding below is a later mapping (Inferred). Every Enterprise binding is either a technique ATT&CK lists for an object it ties to a 2013 report (G0006 APT1, G0044 Winnti Group, S0033 NetTraveler, G0094 Kimsuky, S0051 MiniDuke, G0021 Molerats, S0027 Zeroaccess, S0041 Wiper) or this study's mapping of a behavior a source describes. Every id was checked against the library's data files (`data/attack/technique_profiles.jsonl`, `group_to_technique.jsonl`, `software_to_technique.jsonl`, `software_profiles.jsonl`, `groups.jsonl`, `software.jsonl`, `campaigns.jsonl`, `technique_to_d3fend.jsonl`, `data/attack/ics/` and `data/weaknesses/`) and against the generated pages under `mitre/` on 12 and 13 November 2026 (Demonstrated [123][124][125]). Names and tactics are those of ATT&CK v20.0 as the library carries them, including the v20.0 tactics stealth and defense-impairment (Demonstrated [123]).

The Basis column says how strong each tie is, as in the [2016 chronicle](/case-studies/CHRONICLE_2016.md). **Listed** means ATT&CK itself lists the id for the object. **Described** means a primary source describes the behavior and this study assigns the id. **Reported** means only a Reported source describes it. **Inferred** means the mapping rests on this study's reading. Three caveats apply to the Listed rows: APT1's record has 23 techniques and only the 22 that cite the Mandiant report are bound; Kimsuky's record spans years of reporting and only the 16 entries that cite Kaspersky's 2013 report are bound; and the citations behind the NetTraveler, Zeroaccess and Wiper entries were not opened (Confirmed [10][51]; Demonstrated [123]).

### ATT&CK Enterprise techniques

| Id | Name (ATT&CK v20.0) | Tactic(s) | Basis | Dated event or report | Sources |
|---|---|---|---|---|---|
| [`T1583.001`](/mitre/techniques/T1583-001.md) | Domains | resource-development | Listed (G0006, G0044) | APT1 report (19 Feb); Winnti (11 Apr) | [10][45] |
| [`T1584.001`](/mitre/techniques/T1584-001.md) | Domains | resource-development | Listed (G0006) | APT1 report (19 Feb) | [10] |
| [`T1585.002`](/mitre/techniques/T1585-002.md) | Email Accounts | resource-development | Listed (G0006) | APT1 report (19 Feb) | [10] |
| [`T1588.001`](/mitre/techniques/T1588-001.md) | Malware | resource-development | Listed (G0006) | APT1 report (19 Feb) | [10] |
| [`T1588.002`](/mitre/techniques/T1588-002.md) | Tool | resource-development | Listed (G0006) | APT1 report (19 Feb) | [10] |
| [`T1566`](/mitre/techniques/T1566.md) | Phishing | initial-access | Described | ICS-CERT's 2013 incident vectors include spear-phishing | [95] |
| [`T1566.001`](/mitre/techniques/T1566-001.md) | Spearphishing Attachment | initial-access | Listed (G0006, G0094); Described | APT1 report (19 Feb); Kimsuky (11 Sep); NetTraveler's spearphishing (4 Jun); Icefog's lure documents (25 Sep); CryptoLocker's attachments (TA13-309A, 5 Nov) | [10][51][46][31][35] |
| [`T1566.002`](/mitre/techniques/T1566-002.md) | Spearphishing Link | initial-access | Listed (G0006) | APT1 report (19 Feb) | [10] |
| [`T1189`](/mitre/techniques/T1189.md) | Drive-by Compromise | initial-access | Described | Java CVE-2013-0422 via malicious applets (TA13-010A, 10 Jan); news sites to Fiesta (16 May); IE8 watering holes (May, Sep); US security-policy site (12 Nov); ICS-CERT's watering-hole notices | [2][21][19][29][37][95] |
| [`T1190`](/mitre/techniques/T1190.md) | Exploit Public-Facing Application | initial-access | Described | Drinkman ring's SQL injection (25 Jul, as charged); DOE MIS (Jul); ICS-CERT's SQL injection and web-service vectors; Struts S2-016 and ColdFusion in KEV (match Inferred) | [68][25][95][79][72] |
| [`T1195.002`](/mitre/techniques/T1195-002.md) | Compromise Software Supply Chain | initial-access | Described | Winnti's trojan pushed from a game publisher's update server (11 Apr) | [16] |
| [`T1199`](/mitre/techniques/T1199.md) | Trusted Relationship | initial-access | Reported | Target, through an HVAC vendor's network access (Nov) | [40] |
| [`T1078`](/mitre/techniques/T1078.md) | Valid Accounts | stealth, persistence, privilege-escalation, initial-access | Reported | Target, credentials reportedly stolen from the vendor (Nov) | [40] |
| [`T1059.003`](/mitre/techniques/T1059-003.md) | Windows Command Shell | execution | Listed (G0006) | APT1 report (19 Feb) | [10] |
| [`T1072`](/mitre/techniques/T1072.md) | Software Deployment Tools | execution, lateral-movement | Listed (S0041) | Wiper in the March 2013 South Korea attack, per ATT&CK's description | [123][49] |
| [`T1203`](/mitre/techniques/T1203.md) | Exploitation for Client Execution | execution | Described | Java CVE-2013-0422 (Jan); Reader CVE-2013-0640 in MiniDuke's PDFs (27 Feb); IE CVE-2013-1347 (May) and CVE-2013-3893 (Sep); Office CVE-2013-3906 (Nov); Icefog's and NetTraveler's known exploits | [3][52][20][29][36][31][46] |
| [`T1204.002`](/mitre/techniques/T1204-002.md) | Malicious File | execution | Described | CryptoLocker's attachments (5 Nov); FinSpy's Ginbot 7 bait (13 Mar) | [35][64] |
| [`T1547.001`](/mitre/techniques/T1547-001.md) | Registry Run Keys / Startup Folder | persistence, privilege-escalation | Listed (G0094) | Kimsuky (11 Sep) | [51] |
| [`T1543.003`](/mitre/techniques/T1543-003.md) | Windows Service | persistence, privilege-escalation | Listed (G0094) | Kimsuky (11 Sep) | [51] |
| [`T1546.001`](/mitre/techniques/T1546-001.md) | Change Default File Association | privilege-escalation, persistence | Listed (G0094) | Kimsuky (11 Sep) | [51] |
| [`T1068`](/mitre/techniques/T1068.md) | Exploitation for Privilege Escalation | privilege-escalation | Described | NDProxy CVE-2013-5065, exploited in limited targeted attacks (Nov) | [39][85] |
| [`T1055`](/mitre/techniques/T1055.md) | Process Injection | stealth, privilege-escalation | Listed (G0094) | Kimsuky (11 Sep) | [51] |
| [`T1014`](/mitre/techniques/T1014.md) | Rootkit | stealth | Listed (G0044, S0027) | Winnti (11 Apr); ZeroAccess kernel-mode rootkit (disrupted 5 Dec) | [45][90] |
| [`T1027.003`](/mitre/techniques/T1027-003.md) | Steganography | stealth | Described | MiniDuke receives payloads inside GIF files (27 Feb) | [52] |
| [`T1036.005`](/mitre/techniques/T1036-005.md) | Match Legitimate Resource Name or Location | stealth | Listed (G0006); Described | APT1 report (19 Feb); a FinSpy sample masquerading as Mozilla Firefox (30 Apr) | [10][65] |
| [`T1070.004`](/mitre/techniques/T1070-004.md) | File Deletion | stealth | Listed (G0094) | Kimsuky (11 Sep) | [51] |
| [`T1564.004`](/mitre/techniques/T1564-004.md) | NTFS File Attributes | stealth | Listed (S0027) | ZeroAccess (disrupted 5 Dec) | [90] |
| [`T1553.002`](/mitre/techniques/T1553-002.md) | Code Signing | defense-impairment | Listed (G0044, G0021) | Winnti's stolen certificates (11 Apr); Molerats' forged Microsoft certificates (23 Aug, as ATT&CK cites) | [45][57] |
| [`T1685`](/mitre/techniques/T1685.md) | Disable or Modify Tools | defense-impairment | Listed (G0094) | Kimsuky (11 Sep) | [51] |
| [`T1686`](/mitre/techniques/T1686.md) | Disable or Modify System Firewall | defense-impairment | Listed (G0094) | Kimsuky disables firewalls (11 Sep) | [51][50] |
| [`T1003.001`](/mitre/techniques/T1003-001.md) | LSASS Memory | credential-access | Listed (G0006) | APT1 report (19 Feb) | [10] |
| [`T1040`](/mitre/techniques/T1040.md) | Network Sniffing | credential-access, discovery | Described | Drinkman ring's sniffers (25 Jul, as charged) | [68] |
| [`T1110.001`](/mitre/techniques/T1110-001.md) | Password Guessing | credential-access | Described | WordPress admin brute force (15 Apr) | [17] |
| [`T1056.001`](/mitre/techniques/T1056-001.md) | Keylogging | collection, credential-access | Listed (S0033, G0094); Described | NetTraveler (4 Jun); Kimsuky (11 Sep); Citadel's banking keylogger (5 Jun) | [47][51][23] |
| [`T1087.001`](/mitre/techniques/T1087-001.md) | Local Account | discovery | Listed (G0006) | APT1 report (19 Feb) | [10] |
| [`T1083`](/mitre/techniques/T1083.md) | File and Directory Discovery | discovery | Listed (G0044, G0094) | Winnti (11 Apr); Kimsuky (11 Sep) | [45][51] |
| [`T1057`](/mitre/techniques/T1057.md) | Process Discovery | discovery | Listed (G0006, G0044) | APT1 report (19 Feb); Winnti (11 Apr) | [10][45] |
| [`T1016`](/mitre/techniques/T1016.md) | System Network Configuration Discovery | discovery | Listed (G0006) | APT1 report (19 Feb) | [10] |
| [`T1049`](/mitre/techniques/T1049.md) | System Network Connections Discovery | discovery | Listed (G0006) | APT1 report (19 Feb) | [10] |
| [`T1007`](/mitre/techniques/T1007.md) | System Service Discovery | discovery | Listed (G0006) | APT1 report (19 Feb) | [10] |
| [`T1135`](/mitre/techniques/T1135.md) | Network Share Discovery | discovery | Listed (G0006) | APT1 report (19 Feb) | [10] |
| [`T1010`](/mitre/techniques/T1010.md) | Application Window Discovery | discovery | Listed (S0033) | NetTraveler (4 Jun) | [47] |
| [`T1082`](/mitre/techniques/T1082.md) | System Information Discovery | discovery | Listed (G0094) | Kimsuky (11 Sep) | [51] |
| [`T1680`](/mitre/techniques/T1680.md) | Local Storage Discovery | discovery | Listed (G0094) | Kimsuky (11 Sep) | [51] |
| [`T1550.002`](/mitre/techniques/T1550-002.md) | Pass the Hash | lateral-movement | Listed (G0006) | APT1 report (19 Feb) | [10] |
| [`T1005`](/mitre/techniques/T1005.md) | Data from Local System | collection | Listed (G0006, G0094); Described | APT1 report (19 Feb); Kimsuky (11 Sep); Drinkman ring (25 Jul, as charged) | [10][51][68] |
| [`T1114.001`](/mitre/techniques/T1114-001.md) | Local Email Collection | collection | Listed (G0006) | APT1 report (19 Feb) | [10] |
| [`T1114.002`](/mitre/techniques/T1114-002.md) | Remote Email Collection | collection | Listed (G0006) | APT1 report (19 Feb) | [10] |
| [`T1119`](/mitre/techniques/T1119.md) | Automated Collection | collection | Listed (G0006) | APT1 report (19 Feb) | [10] |
| [`T1125`](/mitre/techniques/T1125.md) | Video Capture | collection | Described | A DHS-themed ransomware variant photographs the victim through the webcam (21 Mar) | [11] |
| [`T1560.001`](/mitre/techniques/T1560-001.md) | Archive via Utility | collection | Listed (G0006) | APT1 report (19 Feb) | [10] |
| [`T1560.003`](/mitre/techniques/T1560-003.md) | Archive via Custom Method | collection | Listed (G0094) | Kimsuky (11 Sep) | [51] |
| [`T1008`](/mitre/techniques/T1008.md) | Fallback Channels | command-and-control | Listed (S0051) | MiniDuke (27 Feb) | [53][52] |
| [`T1102.001`](/mitre/techniques/T1102-001.md) | Dead Drop Resolver | command-and-control | Listed (S0051) | MiniDuke finds its server through Twitter and Google Search (27 Feb) | [53][52] |
| [`T1105`](/mitre/techniques/T1105.md) | Ingress Tool Transfer | command-and-control | Listed (G0044, S0051) | Winnti (11 Apr); MiniDuke (27 Feb) | [45][53] |
| [`T1219.002`](/mitre/techniques/T1219-002.md) | Remote Desktop Software | command-and-control | Listed (G0094) | Kimsuky's modified TeamViewer (11 Sep) | [51][50] |
| [`T1041`](/mitre/techniques/T1041.md) | Exfiltration Over C2 Channel | exfiltration | Listed (G0094) | Kimsuky (11 Sep) | [51] |
| [`T1498`](/mitre/techniques/T1498.md) | Network Denial of Service | impact | Described | The 2011 to 2013 financial-sector DDoS, as charged | [27][28] |
| [`T1498.002`](/mitre/techniques/T1498-002.md) | Reflection Amplification | impact | Described | Spamhaus DNS reflection (18 to 22 Mar); TA13-088A (29 Mar) | [12][13][14] |
| [`T1486`](/mitre/techniques/T1486.md) | Data Encrypted for Impact | impact | Described | CryptoLocker (TA13-309A, 5 Nov) | [35] |

Left out on purpose: APT1's T1021.001, which cites a 2014 source [10]; the 19 Ke3chang techniques, whose source could not be opened and whose 2013 date is inferred [48]; Operation Ghost's eight techniques (T1583.001, T1001.002, T1587.001, T1585.001, T1546.003, T1027.003, T1078.002, T1102.002), which ATT&CK records across September 2013 to October 2019 without a 2013 date for any one of them [54]; MiniDuke's other ATT&CK entries, which do not cite the 2013 report [53]; P2P ZeuS's T1001.001, whose disruption belongs to 2014 [91][82]; FinFisher's entries, whose citations were not checked [65]; any technique for the Snowden press accounts, the New York Times intrusion and the NYT's routing claim, which rest on Reported sources [60][61][62][63][5]; any technique for Adobe, Yahoo, Liberty Reserve and Silk Road, whose primaries describe no intrusion method or describe crimes and remedies [32][89][66][67]; any technique for the D-Link, ePO, IPMI and Rails disclosures, for which no exploitation is recorded in the sources opened [34][24][80][71]; Citadel's blocking of anti-malware sites, which no single technique describes well [104]; and ZeroAccess's click fraud [41].

### ATT&CK for ICS

The library has no generated pages for ICS techniques, so the ids are plain text; names and tactics are those in `data/attack/ics/` (Demonstrated [123][125]). No ICS layer is saved for this chronicle.

| Id | Name (ATT&CK for ICS v20.0) | Tactic(s) | Basis | Dated event or report | Sources |
|---|---|---|---|---|---|
| T0883 | Internet Accessible Device | initial-access | Inferred | ICS-CERT's 2013 incidents: unauthorized access of internet-facing devices | [95] |
| T0847 | Replication Through Removable Media | initial-access | Inferred | ICS-CERT's 2013 incidents: removable media | [95] |
| T0817 | Drive-by Compromise | initial-access | Inferred | ICS-CERT's watering-hole notifications to more than 50 organizations | [95] |
| T0819 | Exploit Public-Facing Application | initial-access | Inferred | ICS-CERT's 2013 incidents: SQL injection and externally facing web services | [95] |

The Bowman Avenue Dam intrusion and the DNP3 advisories are not bound: the first is a charge with no technical description in the source opened, and the second are disclosures, not attacks (Confirmed [28][95]; Inferred).

### ATT&CK groups, software and campaigns

| Object | Id | Binding | Sources |
|---|---|---|---|
| APT1 | [G0006](/mitre/groups/G0006.md) | Bound: Mandiant report, 19 Feb 2013; 22 of 23 techniques | [10][43][121] |
| BISCUIT, Cachedump, CALENDAR, GLOOXMAIL, gsecdump, ipconfig, Lslsass, Mimikatz, Net, Pass-The-Hash Toolkit, PoisonIvy, PsExec, pwdump, Seasalt, Tasklist, WEBC2, xCmd | [S0017](/mitre/software/S0017.md), [S0119](/mitre/software/S0119.md), [S0025](/mitre/software/S0025.md), [S0026](/mitre/software/S0026.md), [S0008](/mitre/software/S0008.md), [S0100](/mitre/software/S0100.md), [S0121](/mitre/software/S0121.md), [S0002](/mitre/software/S0002.md), [S0039](/mitre/software/S0039.md), [S0122](/mitre/software/S0122.md), [S0012](/mitre/software/S0012.md), [S0029](/mitre/software/S0029.md), [S0006](/mitre/software/S0006.md), [S0345](/mitre/software/S0345.md), [S0057](/mitre/software/S0057.md), [S0109](/mitre/software/S0109.md), [S0123](/mitre/software/S0123.md) | Context: ATT&CK lists them for G0006; their own techniques are not bound | [10] |
| Winnti Group | [G0044](/mitre/groups/G0044.md) | Bound: Kaspersky, 11 Apr 2013; all six techniques | [45][16] |
| Winnti for Windows, PlugX | [S0141](/mitre/software/S0141.md), [S0013](/mitre/software/S0013.md) | Context: ATT&CK lists them for G0044 | [45] |
| NetTraveler | [S0033](/mitre/software/S0033.md) | Bound with a caveat: Kaspersky, 4 Jun 2013; both techniques; citations not opened | [47][46] |
| TA459 | [G0062](/mitre/groups/G0062.md) | Context: associated with S0033 | [47] |
| Kimsuky | [G0094](/mitre/groups/G0094.md) | Bound with a caveat: Kaspersky, 11 Sep 2013; the 16 entries that cite it | [51][50] |
| MiniDuke | [S0051](/mitre/software/S0051.md) | Bound: Kaspersky and CrySyS, 27 Feb 2013; the three entries that cite it | [53][52] |
| APT29 | [G0016](/mitre/groups/G0016.md) | Context: uses S0051; SVR attribution from 2021 statements | [53] |
| Operation Ghost | [C0023](/mitre/campaigns/C0023.md) | Context only: first seen Sep 2013, last seen Oct 2019; software [S0512](/mitre/software/S0512.md) FatDuke, [S0051](/mitre/software/S0051.md), [S0518](/mitre/software/S0518.md) PolyglotDuke, [S0029](/mitre/software/S0029.md), [S0511](/mitre/software/S0511.md) RegDuke | [54][55] |
| Molerats | [G0021](/mitre/groups/G0021.md) | Bound: one technique, T1553.002, citing FireEye's 23 Aug 2013 report | [57] |
| Zeroaccess | [S0027](/mitre/software/S0027.md) | Bound with a caveat: disrupted 5 Dec 2013; both techniques; citations not opened | [90][41] |
| Wiper | [S0041](/mitre/software/S0041.md) | Bound with a caveat: ATT&CK describes it as used in March 2013 against South Korean banks and media; one technique; citation not opened | [123][49] |
| Lazarus Group | [G0032](/mitre/groups/G0032.md) | Context only: malware correlates to Operation Troy and DarkSeoul; no technique entry cites a 2013 report | [15] |
| Ke3chang | [G0004](/mitre/groups/G0004.md) | Context only: 19 techniques cite a 2014 report that could not be opened; 2013 date Inferred | [48] |
| APT17 | [G0025](/mitre/groups/G0025.md) | Context only: alias Deputy Dog; cites only a 2015 report | [123] |
| APT12 | [G0005](/mitre/groups/G0005.md) | Not bound: does not cite the New York Times case | [123] |
| Gamaredon Group, APT33, CopyKittens, Silent Librarian, Carbanak | [G0047](/mitre/groups/G0047.md), [G0064](/mitre/groups/G0064.md), [G0052](/mitre/groups/G0052.md), [G0122](/mitre/groups/G0122.md), [G0008](/mitre/groups/G0008.md) | Context only: ATT&CK dates their activity from at least 2013 | [56][58][42] |
| P2P ZeuS | [S0016](/mitre/software/S0016.md) | Context only: GameOver Zeus, disrupted in 2014 | [91][82] |
| FinFisher | [S0182](/mitre/software/S0182.md) | Context only: 2013 citations not checked | [123] |

The library's ATT&CK data has no object for Red October, Icefog, Citadel, CryptoLocker, Reveton, Blackhole, the Fiesta kit, the ITSecTeam and Mersad campaign or the Syrian Electronic Army (Demonstrated [123]).

### CWE and CAPEC

The CWE column names the source of each id. Names are those in the library's CWE and CAPEC data, and every CAPEC listed has a page under `/mitre/capec/` (Demonstrated [124][125]). The library has no per-CWE generated pages, so CWE ids are plain text; the [CWE reference](/CWE_REFERENCE.md) is the library's entry point.

| CWE | Weakness (library name) | Basis | 2013 record | CAPEC |
|---|---|---|---|---|
| CWE-416 | Use After Free | NVD [20][74][128] | IE CVE-2013-1347 (May), CVE-2013-2551 (Mar), CVE-2013-3893 (Sep; KEV lists CWE-399) | None (the library relates none to these flaws) |
| CWE-787 | Out-of-bounds Write | NVD; KEV | ActiveX CVE-2013-3918 (Nov); Reader CVE-2013-0640 (Feb) | None assigned |
| CWE-94 | Improper Control of Generation of Code | NVD [129]; KEV [4] | TIFF CVE-2013-3906 (Nov); Office CVE-2012-0158, used by NetTraveler and Icefog | None assigned |
| CWE-284 | Improper Access Control | NVD | Java CVE-2013-0422 (Jan) | None assigned |
| CWE-120 | Buffer Copy without Checking Size of Input | KEV | Reader CVE-2013-0641 (Feb) | None assigned |
| CWE-287 | Improper Authentication | NVD | ColdFusion CVE-2013-0625 (Jan) | None assigned |
| CWE-693 | Protection Mechanism Failure | NVD | Java CVE-2013-2465 (Jun) | None assigned |
| CWE-74 | Improper Neutralization of Special Elements in Output Used by a Downstream Component | NVD [131] | Struts CVE-2013-2251 (Jul) | None assigned |
| CWE-347 | Improper Verification of Cryptographic Signature | NVD [130] | WinVerifyTrust CVE-2013-3900 (Dec) | None assigned |
| CWE-20 | Improper Input Validation | NVD [132] | Rails CVE-2013-0156 (Jan) | None assigned |
| CWE-326, CWE-327 | Inadequate Encryption Strength; Use of a Broken or Risky Cryptographic Algorithm | NVD | RC4 biases, CVE-2013-2566 (Mar) | None assigned |
| CWE-310, CWE-189, CWE-255, CWE-399 | (categories, as NVD or KEV lists them; not in the library's CWE data) | NVD [118][77][134]; KEV [4] | Lucky Thirteen CVE-2013-0169; Linux CVE-2013-2094; IPMI CVE-2013-4786; KEV's entry for CVE-2013-3893 | None; not bound |
| CWE-89 | Improper Neutralization of Special Elements used in an SQL Command | Study's pairing through CAPEC-66's related weakness | Drinkman ring's SQL injection (Jul, as charged); ICS-CERT's SQL injection vector (Inferred) | [CAPEC-66](/mitre/capec/CAPEC-66.md) SQL Injection |
| none bound | (reflection) | Library data | Spamhaus; TA13-088A | [CAPEC-490](/mitre/capec/CAPEC-490.md) Amplification (on T1498.002) |
| none bound | (spearphishing) | Library data | APT1; Kimsuky; NetTraveler; Icefog; CryptoLocker | [CAPEC-163](/mitre/capec/CAPEC-163.md) Spear Phishing (on T1566.001 and T1566.002) |
| none bound | (credentials) | Library data | APT1; WordPress; Citadel, NetTraveler and Kimsuky; Target (Reported) | [CAPEC-644](/mitre/capec/CAPEC-644.md) Use of Captured Hashes (Pass The Hash) (on T1550.002); [CAPEC-555](/mitre/capec/CAPEC-555.md) Remote Services with Stolen Credentials (on T1114.002); [CAPEC-49](/mitre/capec/CAPEC-49.md) Password Brute Forcing (on T1110.001); [CAPEC-568](/mitre/capec/CAPEC-568.md) Capture Credentials via Keylogger (on T1056.001); [CAPEC-560](/mitre/capec/CAPEC-560.md) Use of Known Domain Credentials (on T1078) |
| none bound | (code signing and rootkits) | Library data | Winnti; Molerats; ZeroAccess | [CAPEC-68](/mitre/capec/CAPEC-68.md) Subvert Code-signing Facilities, [CAPEC-206](/mitre/capec/CAPEC-206.md) Signing Malicious Code and [CAPEC-473](/mitre/capec/CAPEC-473.md) Signature Spoof (on T1553.002); [CAPEC-552](/mitre/capec/CAPEC-552.md) Install Rootkit (on T1014) |

### D3FEND countermeasures

The technique-to-countermeasure links come from the library's D3FEND data; pairing them with the 2013 record is this study's reading (Demonstrated [123]; Inferred). Every page exists under `/mitre/d3fend/` (Demonstrated [125]).

| Technique or event from the record | D3FEND countermeasures (D3FEND tactic) | 2013 analogue |
|---|---|---|
| T1189, T1203, T1068 | [Process Segment Execution Prevention](/mitre/d3fend/process-segment-execution-prevention.md) (Harden); [Segment Address Offset Randomization](/mitre/d3fend/segment-address-offset-randomization.md) (Harden); [Stack Frame Canary Validation](/mitre/d3fend/stack-frame-canary-validation.md) (Harden); [Memory Boundary Tracking](/mitre/d3fend/memory-boundary-tracking.md) (Detect); [URL Reputation Analysis](/mitre/d3fend/url-reputation-analysis.md) and [URL Analysis](/mitre/d3fend/url-analysis.md) (Detect, on T1189) | Java, IE, Reader and Office exploitation [3][20][29][36][73]; NDProxy [39] |
| T1566.001, T1566.002, T1204.002 | [Email Filtering](/mitre/d3fend/email-filtering.md) (Isolate); [File Analysis](/mitre/d3fend/file-analysis.md) (Detect); [Dynamic Analysis](/mitre/d3fend/dynamic-analysis.md) (Detect); [Sender Reputation Analysis](/mitre/d3fend/sender-reputation-analysis.md) (Detect); [Executable Allowlisting](/mitre/d3fend/executable-allowlisting.md) (Isolate, on T1204.002) | APT1 [10]; Kimsuky [50]; Icefog [31]; CryptoLocker [35] |
| T1486 | [Restore File](/mitre/d3fend/restore-file.md) (Restore); [File Integrity Monitoring](/mitre/d3fend/file-integrity-monitoring.md) (Detect); [Decoy File](/mitre/d3fend/decoy-file.md) (Deceive) | CryptoLocker [35] |
| T1498.002 | [Inbound Traffic Filtering](/mitre/d3fend/inbound-traffic-filtering.md) (Isolate); [Inbound Session Volume Analysis](/mitre/d3fend/inbound-session-volume-analysis.md) (Detect); [Network Traffic Filtering](/mitre/d3fend/network-traffic-filtering.md) (Isolate) | Spamhaus [12][13]; TA13-088A [14] |
| T1190 | [Inbound Traffic Filtering](/mitre/d3fend/inbound-traffic-filtering.md) (Isolate); [Database Query String Analysis](/mitre/d3fend/database-query-string-analysis.md) (Detect); [Client-server Payload Profiling](/mitre/d3fend/client-server-payload-profiling.md) (Detect) | Drinkman ring [68]; DOE MIS [25] |
| T1199, T1078 | [Remote Terminal Session Detection](/mitre/d3fend/remote-terminal-session-detection.md) (Detect); [Connection Attempt Analysis](/mitre/d3fend/connection-attempt-analysis.md) (Detect); [Session Termination](/mitre/d3fend/session-termination.md) (Evict); [Account Locking](/mitre/d3fend/account-locking.md) (Evict); [User Account Permissions](/mitre/d3fend/user-account-permissions.md) (Isolate); [Access Modeling](/mitre/d3fend/access-modeling.md) (Model) | Target's vendor access (Reported) [40] |
| T1110.001 | [Strong Password Policy](/mitre/d3fend/strong-password-policy.md) (Harden); [Credential Hardening](/mitre/d3fend/credential-hardening.md) (Harden); [Multi-factor Authentication](/mitre/d3fend/multi-factor-authentication.md) (Harden); [Change Default Password](/mitre/d3fend/change-default-password.md) (Harden) | WordPress "admin" accounts [17] |
| T1003.001 | [Process Spawn Analysis](/mitre/d3fend/process-spawn-analysis.md) (Detect); [Kernel-based Process Isolation](/mitre/d3fend/kernel-based-process-isolation.md) (Isolate); [Hardware-based Process Isolation](/mitre/d3fend/hardware-based-process-isolation.md) (Isolate) | APT1 [10] |
| T1056.001, T1125 | [Input Device Analysis](/mitre/d3fend/input-device-analysis.md) (Detect); [Hardware Component Inventory](/mitre/d3fend/hardware-component-inventory.md) (Model); [IO Port Restriction](/mitre/d3fend/io-port-restriction.md) (Isolate) | Citadel [23]; NetTraveler [46]; Kimsuky [50]; the webcam variant [11] |
| T1014, T1195.002 | [File Integrity Monitoring](/mitre/d3fend/file-integrity-monitoring.md) (Detect); [Firmware Verification](/mitre/d3fend/firmware-verification.md) (Detect, on T1014); [Software Inventory](/mitre/d3fend/software-inventory.md) (Model); [Software Update](/mitre/d3fend/software-update.md) (Harden); [Restore Software](/mitre/d3fend/restore-software.md) (Restore) | Winnti [16]; ZeroAccess [90] |
| T1008, T1105 | [Outbound Traffic Filtering](/mitre/d3fend/outbound-traffic-filtering.md) (Isolate); [Relay Pattern Analysis](/mitre/d3fend/relay-pattern-analysis.md) (Detect) | MiniDuke [52]; Winnti [16] |
| The year's TLS weaknesses | [Certificate Pinning](/mitre/d3fend/certificate-pinning.md) and [Message Encryption](/mitre/d3fend/message-encryption.md) (study's pairing) | Lucky Thirteen and RC4 [117][119]; RFC 6962 [115] (Inferred) |

The library links T1498, T1553.002, T1550.002, T1102.001, T1219.002 and T1564.004 to no D3FEND countermeasure (Demonstrated [123]). ATT&CK mitigation pages exist for [M1051 Update Software](/mitre/mitigations/M1051.md), [M1050 Exploit Protection](/mitre/mitigations/M1050.md), [M1048 Application Isolation and Sandboxing](/mitre/mitigations/M1048.md), [M1042 Disable or Remove Feature or Program](/mitre/mitigations/M1042.md), [M1021 Restrict Web-Based Content](/mitre/mitigations/M1021.md), [M1017 User Training](/mitre/mitigations/M1017.md), [M1053 Data Backup](/mitre/mitigations/M1053.md), [M1037 Filter Network Traffic](/mitre/mitigations/M1037.md), [M1030 Network Segmentation](/mitre/mitigations/M1030.md), [M1035 Limit Access to Resource Over Network](/mitre/mitigations/M1035.md), [M1032 Multi-factor Authentication](/mitre/mitigations/M1032.md), [M1027 Password Policies](/mitre/mitigations/M1027.md), [M1026 Privileged Account Management](/mitre/mitigations/M1026.md), [M1036 Account Use Policies](/mitre/mitigations/M1036.md), [M1018 User Account Management](/mitre/mitigations/M1018.md) and [M1047 Audit](/mitre/mitigations/M1047.md) (Demonstrated [125]). TA13-010A's advice to disable Java in browsers maps most closely to M1042 and M1021; the Fix it shims and Advisory workarounds to M1050; TA13-088A's resolver advice to M1037; and TA13-309A's backup advice to M1053 (Inferred [2][29][14][35]).

### Navigator layer

The study's Enterprise techniques are saved as one ATT&CK Navigator layer pinned to ATT&CK v20, [navigator/library-layers/chronicle-2013.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/chronicle-2013.json), in the format of the existing chronicle layers: domain enterprise-attack, described as a curated case-study layer and not an official MITRE mapping (Demonstrated [126]). It lists the 60 techniques in the Enterprise table under each tactic they carry in v20.0, 70 technique-tactic entries in all, and is listed on [the Navigator layers page](/navigator/index.md). The ICS techniques are not in it. Scores show the basis, not severity, in the house scale set by the 2016 chronicle: 100 where an ATT&CK object prints the id, 70 where a primary source describes the behavior and this study assigns the id, 50 where only a Reported source supports it, and 40 for an Inferred mapping (Demonstrated [126]). The 44 techniques listed for G0006, G0044, S0033, G0094, S0051, G0021, S0027 or S0041 score 100, with a comment naming the object and the 2013 report its entries cite; T1566, T1189, T1190, T1195.002, T1203, T1204.002, T1068, T1027.003, T1040, T1110.001, T1125, T1498, T1498.002 and T1486 score 70; T1199 and T1078 score 50. No technique scores 40. Each entry's comment names the source numbers in the Sources table below.

## Cross-cutting themes

**Attribution went public, but mostly not from governments.** Mandiant named a PLA unit, Kaspersky described half a dozen campaigns and named no state for most, and the government statements that tie 2013 activity to states came in 2014, 2016 and 2021 (Confirmed [43][1][46][31][49][27][53]; Inferred for the reading).

**The client was the front door.** The year's exploited flaws sit in Java, Internet Explorer, Reader and Office, delivered by exploit kits, watering holes and lure documents (Confirmed [3][20][29][36][73][21][37]).

**Reflection made DDoS cheap.** Spamhaus's attackers borrowed open resolvers, and the Iranian bank campaign, as charged, ran for three years (Confirmed [12][14]; Confirmed as charged [27]).

**Ransomware learned to encrypt.** Lock-screen ransomware, which the FBI says Citadel delivered, was joined in November by CryptoLocker's file encryption and three-day deadline (Confirmed [11][84][35]).

**Money became a target for takedowns.** Treasury's first Section 311 action against a virtual currency provider and the Silk Road bitcoin seizure joined Microsoft's civil actions against Citadel and ZeroAccess (Confirmed [22][67][23][41]).

**Breaches were found by someone else, or found late.** Target heard from the Justice Department, Yahoo found its 2013 theft in 2016, and the DOE system had two earlier incidents, in May 2011 and January 2012 (Confirmed [40][89][25]).

**Policy turned toward frameworks.** The executive order, PPD-21, SP 800-53 Rev. 4, ISO/IEC 27002:2013, the EU strategy and the UN expert report all date from 2013, and most of their effects arrived in 2014 and later (Confirmed [96][7][98][110][101][102]; Inferred for the reading).

### What is overstated and what is understated

This section is the study's reading of the record (Inferred).

- **Overstated: the year as a story of named breaches.** 2013 is remembered for Target and Adobe and their headline counts, but the dated defender record is dominated by standards and programs (SP 800-53 Rev. 4, the executive order and PPD-21, ISO/IEC 27002:2013, the CVE syntax change, Certificate Transparency, Microsoft's bounties) whose effects arrived in 2014 and later [96][98][110][111][115][116].
- **Overstated: Target's point of entry as a finding.** The HVAC-vendor account in the Senate report rests, by the report's own account, on media reports and expert analyses [40].
- **Overstated: the attribution behind the 2013 vendor reports.** Red October, NetTraveler and Icefog name no state, Kimsuky calls North Korea "the likely theory", and MiniDuke was tied to the SVR only through ATT&CK's use of 2021 statements [1][46][31][50][53].
- **Overstated: the New York Times attribution.** It rests on the paper and its consultants, not a government record [5].
- **Overstated: the dollar and infection figures.** Citadel's half a billion dollars and five million people are Microsoft's estimates, ZeroAccess's USD 2.7 million a month is Microsoft's, the 300 Gbps Spamhaus figure is relayed second-hand, and Liberty Reserve's USD 6 billion is an allegation [23][41][13][66].
- **Overstated: the precision of ids on 2013 events.** No 2013 event had a contemporaneous ATT&CK mapping, CryptoLocker and the Java exploitation bind by technique only, and every technique id here comes from a later record or this study's reasoning [10][35][2].
- **Understated: the APT1 report's own caution.** It says its view is only a small fraction of APT1's activity, and indicators of that kind lose value as infrastructure rotates, which is this study's reading [121].
- **Understated: the TLS weaknesses.** Lucky Thirteen and the RC4 biases were flaws in the specification, and NVD binds CVE-2013-0169 only to the category CWE-310, so its weakness class is under-recorded [117][118][119].
- **Understated: dwell and discovery.** Red October ran from about 2007, Yahoo's August 2013 theft was disclosed in 2016 and widened in 2017, and 120 of ICS-CERT's 256 incidents could not be classified [1][89][92][95].
- **Understated: the long tail of 2013 flaws.** KEV added CVE-2013-3893 and CVE-2013-3918 in 2025, and six 2013 entries carry the known-ransomware flag [4].
- **Understated: industrial exposure.** ICS-CERT recorded watering-hole notices to more than 50 organizations and a campaign against 40 critical infrastructure organizations, mostly energy, in the same year a dam's SCADA systems were allegedly accessed [95][28].

### Discrepancies in the record

- **Spamhaus's first contact.** Cloudflare's first post says Spamhaus asked for help on Tuesday 19 March; its second says Monday 18 March (Confirmed [12][13]).
- **Target's window.** Target's release gives 27 November to 15 December, KrebsOnSecurity relays the same, and the Senate report gives 27 November to 18 December (Confirmed [122][40]; Reported [88]).
- **Target's customer count.** The Senate report gives as many as 110 million customers; Target's own figures were about 40 million card accounts on 19 December and personal data for up to 70 million customers on 10 January 2014 (Confirmed [40][122]).
- **Adobe's count.** Adobe says about 2.9 million customers; US-CERT says up to 3 million (Confirmed [32][33]).
- **Yahoo's count.** The 2016 filing says more than one billion accounts; the 2017 filing and Yahoo's help page say all accounts existing at the time, about three billion (Confirmed [89][92][26]).
- **Citadel's count.** Microsoft's news release gives 1,462 botnets and "more than a thousand"; its blog says more than 1,400 (Confirmed [23][104]).
- **CVE-2013-3893's weakness.** NVD lists CWE-416; KEV lists CWE-399 (Confirmed [128][4]).
- **The APT1 report.** One research pass could not open it; another opened the PDF, whose figures are used here, and whose release month was first inferred from footnotes citing sources accessed on 6 February 2013 before Mandiant's 19 February announcement confirmed it (Confirmed [121][43]).
- **NIST's preliminary framework date.** The executive order set a 240-day deadline for a preliminary framework; NIST's history says a preliminary draft was released on 1 July and requested comments on the Preliminary Framework on 29 October (Confirmed [96][97]).

## Sources

Every external source was opened on 12 November 2026, except the seven NVD records in rows 128 to 134, opened on 13 November 2026, and the library data checks were run on 12 and 13 November 2026, as the Opened column shows. All are checked as of 13 November 2026. Grade is the source's evidence grade as used in this study. Addresses shown as code rather than as links refuse automated link checkers (the twelve NVD API queries and the two sec.gov addresses of the Yahoo and Verizon filings); copy them into a browser to open them.

| # | Source | URL | Opened | Grade |
|---|---|---|---|---|
| 1 | Kaspersky (Securelist), The Red October campaign, 14 Jan 2013 | https://securelist.com/the-red-october-campaign/57647/ | 2026-11-12 | Confirmed (the vendor's findings); Reported (its Russian-speaking judgment) |
| 2 | US-CERT (CISA archive), TA13-010A, Oracle Java 7 Security Manager Bypass Vulnerability, 10 Jan 2013 | https://www.cisa.gov/news-events/alerts/2013/01/10/oracle-java-7-security-manager-bypass-vulnerability | 2026-11-12 | Confirmed |
| 3 | NVD, CVE-2013-0422 (API record and detail page) | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2013-0422` ; https://nvd.nist.gov/vuln/detail/CVE-2013-0422 | 2026-11-12 | Confirmed |
| 4 | CISA, Known Exploited Vulnerabilities catalog (JSON feed, catalog 2026.11.10) | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | 2026-11-12 | Confirmed |
| 5 | The New York Times, Hackers in China Attacked The Times for Last 4 Months, 30 Jan 2013 | https://www.nytimes.com/2013/01/31/technology/chinese-hackers-infiltrate-new-york-times-computers.html | 2026-11-12 | Reported (the paper's and its consultants' account) |
| 6 | Federal Register, Executive Order 13636, Improving Critical Infrastructure Cybersecurity, 78 FR 11739, 19 Feb 2013 | https://www.federalregister.gov/documents/2013/02/19/2013-03915/improving-critical-infrastructure-cybersecurity | 2026-11-12 | Confirmed |
| 7 | The White House (archive), Presidential Policy Directive 21, Critical Infrastructure Security and Resilience, 12 Feb 2013 | https://obamawhitehouse.archives.gov/the-press-office/2013/02/12/presidential-policy-directive-critical-infrastructure-security-and-resil | 2026-11-12 | Confirmed |
| 8 | NIST, NIST Releases Cybersecurity Framework Version 1.0, 12 Feb 2014 | https://www.nist.gov/news-events/news/2014/02/nist-releases-cybersecurity-framework-version-10 | 2026-11-12 | Confirmed |
| 9 | US-CERT (CISA archive), Update: Ongoing Malicious Cyber Activity against U.S. Government and Private Sector Entities, 22 Feb 2013 (revised 1 Mar) | https://www.cisa.gov/news-events/alerts/2013/02/22/update-ongoing-malicious-cyber-activity-against-us-government-and-private-sector-entities | 2026-11-12 | Confirmed |
| 10 | MITRE ATT&CK, G0006 APT1 | https://attack.mitre.org/groups/G0006/ | 2026-11-12 | Confirmed |
| 11 | US-CERT (CISA archive), Recent Reports of DHS-Themed Ransomware (Update), 21 Mar 2013 (revised 29 Jul) | https://www.cisa.gov/news-events/alerts/2013/03/21/recent-reports-dhs-themed-ransomware-update | 2026-11-12 | Confirmed |
| 12 | Cloudflare, The DDoS That Knocked Spamhaus Offline (And How We Mitigated It), 20 Mar 2013 | https://blog.cloudflare.com/the-ddos-that-knocked-spamhaus-offline-and-ho/ | 2026-11-12 | Confirmed (Cloudflare's account) |
| 13 | Cloudflare, The DDoS That Almost Broke the Internet, 27 Mar 2013 | https://blog.cloudflare.com/the-ddos-that-almost-broke-the-internet/ | 2026-11-12 | Confirmed (Cloudflare's measurements); Reported (the relayed Tier 1 figure and the starting figure) |
| 14 | US-CERT (CISA archive), TA13-088A, DNS Amplification Attacks, 29 Mar 2013 | https://www.cisa.gov/news-events/alerts/2013/03/29/dns-amplification-attacks | 2026-11-12 | Confirmed |
| 15 | MITRE ATT&CK, G0032 Lazarus Group | https://attack.mitre.org/groups/G0032/ | 2026-11-12 | Confirmed |
| 16 | Kaspersky (Securelist), Winnti. More than just a game, Apr 2013 | https://securelist.com/winnti-more-than-just-a-game/37029/ | 2026-11-12 | Confirmed (the vendor's findings) |
| 17 | US-CERT (CISA archive), WordPress Sites Targeted by Mass Brute-Force Botnet Attack, 15 Apr 2013 | https://www.cisa.gov/news-events/alerts/2013/04/15/wordpress-sites-targeted-mass-brute-force-botnet-attack | 2026-11-12 | Confirmed; Reported (the press figures it relays) |
| 18 | Microsoft Security Advisory 2847140, 3 May 2013 (updated 14 May) | https://learn.microsoft.com/en-us/security-updates/securityadvisories/2013/2847140 | 2026-11-12 | Confirmed |
| 19 | US-CERT (CISA archive), Microsoft Releases Security Advisory for Internet Explorer, 7 May 2013 | https://www.cisa.gov/news-events/alerts/2013/05/07/microsoft-releases-security-advisory-internet-explorer | 2026-11-12 | Confirmed |
| 20 | NVD, CVE-2013-1347 (API record) | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2013-1347` | 2026-11-12 | Confirmed |
| 21 | US-CERT (CISA archive), TA13-141A, Washington, DC Radio Station Web Site Compromises, 20 May 2013 | https://www.cisa.gov/news-events/alerts/2013/05/20/washington-dc-radio-station-web-site-compromises | 2026-11-12 | Confirmed |
| 22 | US Department of the Treasury, press release jl1956 on Liberty Reserve, 28 May 2013 | https://home.treasury.gov/news/press-releases/jl1956 | 2026-11-12 | Confirmed |
| 23 | Microsoft, Microsoft, financial services and others join forces to combat massive cybercrime ring, 5 Jun 2013 | https://news.microsoft.com/source/2013/06/05/microsoft-financial-services-and-others-join-forces-to-combat-massive-cybercrime-ring/ | 2026-11-12 | Confirmed (the action); Reported (Microsoft's loss and victim estimates) |
| 24 | US-CERT (CISA archive), TA13-193A, Exploit Tool Targets Vulnerabilities in McAfee ePolicy Orchestrator (ePO), 12 Jul 2013 | https://www.cisa.gov/news-events/alerts/2013/07/12/exploit-tool-targets-vulnerabilities-mcafee-epolicy-orchestrator-epo | 2026-11-12 | Confirmed |
| 25 | US Department of Energy, Office of Inspector General, DOE/IG-0900, The Department of Energy's July 2013 Cyber Security Breach, 6 Dec 2013 | https://www.energy.gov/sites/prod/files/2013/12/f5/IG-0900.pdf | 2026-11-12 | Confirmed |
| 26 | Yahoo Help, Account security issues (SLN28451) | https://help.yahoo.com/kb/account/SLN28451.html | 2026-11-12 | Confirmed (the company's account) |
| 27 | FBI, Iranian DDoS Attacks (wanted notice) | https://www.fbi.gov/wanted/cyber/iranian-ddos-attacks | 2026-11-12 | Confirmed (as charged) |
| 28 | FBI, Hamid Firoozi (wanted notice) | https://www.fbi.gov/wanted/cyber/hamid-firoozi | 2026-11-12 | Confirmed (as charged) |
| 29 | US-CERT (CISA archive), Microsoft Releases Security Advisory for Internet Explorer, 18 Sep 2013 | https://www.cisa.gov/news-events/alerts/2013/09/18/microsoft-releases-security-advisory-internet-explorer | 2026-11-12 | Confirmed |
| 30 | Microsoft Security Advisory 2887505, 17 Sep 2013 | https://learn.microsoft.com/en-us/security-updates/securityadvisories/2013/2887505 | 2026-11-12 | Confirmed |
| 31 | Kaspersky (Securelist), The Icefog APT: A Tale of Cloak and Three Daggers, 25 Sep 2013 | https://securelist.com/the-icefog-apt-a-tale-of-cloak-and-three-daggers/57331/ | 2026-11-12 | Confirmed (the vendor's findings) |
| 32 | Adobe, Important Customer Security Announcement (Brad Arkin), 3 Oct 2013 | https://blog.adobe.com/en/publish/2013/10/03/important-customer-security-announcement | 2026-11-12 | Confirmed (the company's account) |
| 33 | US-CERT (CISA archive), Adobe Customer Information and Source Code Compromises, 3 Oct 2013 | https://www.cisa.gov/news-events/alerts/2013/10/03/adobe-customer-information-and-source-code-compromises | 2026-11-12 | Confirmed |
| 34 | US-CERT (CISA archive), Reports of D-Link Router Backdoor, 18 Oct 2013 (revised 21 Oct) | https://www.cisa.gov/news-events/alerts/2013/10/18/reports-d-link-router-backdoor | 2026-11-12 | Confirmed |
| 35 | US-CERT (CISA archive), TA13-309A, CryptoLocker Ransomware Infections, 5 Nov 2013 | https://www.cisa.gov/news-events/alerts/2013/11/05/cryptolocker-ransomware-infections | 2026-11-12 | Confirmed |
| 36 | Microsoft Security Advisory 2896666, 5 Nov 2013 (and MS13-096, 10 Dec 2013) | https://learn.microsoft.com/en-us/security-updates/securityadvisories/2013/2896666 | 2026-11-12 | Confirmed |
| 37 | US-CERT (CISA archive), Microsoft Addresses New Watering Hole Attack in November 2013 Security Bulletin Release, 12 Nov 2013 | https://www.cisa.gov/news-events/alerts/2013/11/12/microsoft-addresses-new-watering-hole-attack-november-2013-security-bulletin-release | 2026-11-12 | Confirmed |
| 38 | NVD, CVE-2013-3918 (API record and detail page) | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2013-3918` ; https://nvd.nist.gov/vuln/detail/CVE-2013-3918 | 2026-11-12 | Confirmed (the record); Inferred (its match to the watering hole) |
| 39 | US-CERT (CISA archive), Microsoft Releases Security Advisory for Microsoft Windows Kernel, 28 Nov 2013 | https://www.cisa.gov/news-events/alerts/2013/11/28/microsoft-releases-security-advisory-microsoft-windows-kernel | 2026-11-12 | Confirmed |
| 40 | US Senate Committee on Commerce, Science, and Transportation, majority staff report, A "Kill Chain" Analysis of the 2013 Target Data Breach, 26 Mar 2014 | https://www.commerce.senate.gov/services/files/24d3c229-4f2f-405d-b8db-a3a67f183883 | 2026-11-12 | Confirmed (dates and figures from Target statements and testimony); Reported (the point of entry and alerts, from press accounts) |
| 41 | Microsoft, Microsoft, the FBI, Europol and industry partners disrupt the notorious ZeroAccess botnet, 5 Dec 2013 | https://news.microsoft.com/2013/12/05/microsoft-the-fbi-europol-and-industry-partners-disrupt-the-notorious-zeroaccess-botnet/ ; https://news.microsoft.com/source/2013/12/05/microsoft-the-fbi-europol-and-industry-partners-disrupt-the-notorious-zeroaccess-botnet/ | 2026-11-12 | Confirmed |
| 42 | MITRE ATT&CK, G0008 Carbanak | https://attack.mitre.org/groups/G0008 | 2026-11-12 | Confirmed |
| 43 | Mandiant (Google Cloud blog), Mandiant Exposes APT1: One of China's Cyber Espionage Units, 19 Feb 2013 | https://cloud.google.com/blog/topics/threat-intelligence/mandiant-exposes-apt1-chinas-cyber-espionage-units | 2026-11-12 | Confirmed (Mandiant's findings) |
| 44 | The White House (archive), Remarks by Tom Donilon, National Security Advisor to the President, 11 Mar 2013 | https://obamawhitehouse.archives.gov/the-press-office/2013/03/11/remarks-tom-donilon-national-security-advisory-president-united-states-a | 2026-11-12 | Confirmed |
| 45 | MITRE ATT&CK, G0044 Winnti Group | https://attack.mitre.org/groups/G0044/ | 2026-11-12 | Confirmed |
| 46 | Kaspersky (Securelist), NetTraveler report on Red Star APT attacks against high-profile victims, 4 Jun 2013 | https://securelist.com/nettraveler-is-running-red-star-apt-attacks-compromise-high-profile-victims/35936/ | 2026-11-12 | Confirmed (the vendor's findings) |
| 47 | MITRE ATT&CK, S0033 NetTraveler | https://attack.mitre.org/software/S0033/ | 2026-11-12 | Confirmed |
| 48 | MITRE ATT&CK, G0004 Ke3chang | https://attack.mitre.org/groups/G0004/ | 2026-11-12 | Confirmed (the page); Inferred (the 2013 dating) |
| 49 | FBI, Update on Sony Investigation, 19 Dec 2014 | https://www.fbi.gov/news/press-releases/update-on-sony-investigation | 2026-11-12 | Confirmed |
| 50 | Kaspersky (Securelist), The Kimsuky Operation: A North Korean APT?, 11 Sep 2013 | https://securelist.com/the-kimsuky-operation-a-north-korean-apt/57915/ | 2026-11-12 | Confirmed (the vendor's findings); Reported (its "likely theory") |
| 51 | MITRE ATT&CK, G0094 Kimsuky | https://attack.mitre.org/groups/G0094/ | 2026-11-12 | Confirmed |
| 52 | Kaspersky (Securelist), The MiniDuke Mystery: PDF 0-day Government Spy Assembler 0x29A Micro Backdoor, 27 Feb 2013 | https://securelist.com/the-miniduke-mystery-pdf-0-day-government-spy-assembler-0x29a-micro-backdoor/31112/ | 2026-11-12 | Confirmed (the vendors' findings) |
| 53 | MITRE ATT&CK, S0051 MiniDuke | https://attack.mitre.org/software/S0051/ | 2026-11-12 | Confirmed |
| 54 | MITRE ATT&CK, C0023 Operation Ghost | https://attack.mitre.org/campaigns/C0023/ | 2026-11-12 | Confirmed |
| 55 | ESET (WeLiveSecurity), Operation Ghost: The Dukes aren't back, they never left, 17 Oct 2019 | https://www.welivesecurity.com/2019/10/17/operation-ghost-dukes-never-left/ | 2026-11-12 | Confirmed (the vendor's findings) |
| 56 | TeamStarWolf library, ATT&CK G0047 Gamaredon Group text in `data/attack/groups.jsonl` (live page not opened) | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/attack/groups.jsonl | 2026-11-12 | Demonstrated |
| 57 | MITRE ATT&CK, G0021 Molerats | https://attack.mitre.org/groups/G0021/ | 2026-11-12 | Confirmed |
| 58 | TeamStarWolf library, ATT&CK G0064 APT33, G0052 CopyKittens and G0122 Silent Librarian text in `data/attack/groups.jsonl` (live pages not opened) | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/attack/groups.jsonl | 2026-11-12 | Demonstrated |
| 59 | FBI, Firas Dardar (wanted notice, Syrian Electronic Army) | https://www.fbi.gov/wanted/cyber/firas-dardar | 2026-11-12 | Confirmed (as charged) |
| 60 | The Guardian, NSA collecting phone records of millions of Verizon customers daily, 6 Jun 2013 | https://www.theguardian.com/world/2013/jun/06/nsa-phone-records-verizon-court-order | 2026-11-12 | Reported |
| 61 | The Guardian, NSA Prism program taps in to user data of Apple, Google and others, 6 Jun 2013 | https://www.theguardian.com/world/2013/jun/06/us-tech-giants-nsa-data | 2026-11-12 | Reported |
| 62 | Der Spiegel, British Spy Agency GCHQ Hacked Belgian Telecoms Firm, 20 Sep 2013 | https://www.spiegel.de/international/europe/british-spy-agency-gchq-hacked-belgian-telecoms-firm-a-923406.html | 2026-11-12 | Reported |
| 63 | Der Spiegel, report on the NSA toolbox for spying on global networks, 29 Dec 2013 | https://www.spiegel.de/international/world/the-nsa-uses-powerful-toolbox-in-effort-to-spy-on-global-networks-a-940969.html | 2026-11-12 | Reported |
| 64 | Citizen Lab, You Only Click Twice: FinFisher's Global Proliferation, 13 Mar 2013 | https://citizenlab.ca/research/you-only-click-twice-finfishers-global-proliferation-2/ | 2026-11-12 | Confirmed (the researchers' findings) |
| 65 | Citizen Lab, For Their Eyes Only: The Commercialization of Digital Spying, 30 Apr 2013 | https://citizenlab.ca/research/for-their-eyes-only-2/ | 2026-11-12 | Confirmed (the researchers' findings) |
| 66 | US Attorney, SDNY (archive), press release on the Liberty Reserve indictment, 28 May 2013 | https://www.justice.gov/archive/usao/nys/pressreleases/May13/LibertyReservePR.php | 2026-11-12 | Confirmed (as charged) |
| 67 | US Attorney, SDNY (archive), press release on the Silk Road bitcoin seizure, 25 Oct 2013 | https://www.justice.gov/archive/usao/nys/pressreleases/October13/SilkRoadSeizurePR.php | 2026-11-12 | Confirmed (as charged) |
| 68 | US Attorney, District of New Jersey (archive), press release on the Drinkman et al. indictment, 25 Jul 2013 | https://www.justice.gov/archive/usao/nj/Press/files/Drinkman,%20Vladimir%20et%20al.%20Indictment%20News%20Release.html | 2026-11-12 | Confirmed (as charged); Inferred (the technique and CAPEC binding) |
| 69 | Oracle, Security Alert for CVE-2013-0422 | https://www.oracle.com/security-alerts/alert-cve-2013-0422.html | 2026-11-12 | Confirmed (its date not checked) |
| 70 | CERT/CC, VU#625617, Java 7 fails to restrict access to privileged code, 10 Jan 2013 (revised 12 Jun) | https://www.kb.cert.org/vuls/id/625617 | 2026-11-12 | Confirmed |
| 71 | Ruby on Rails, Rails 3.2.11, 3.1.10, 3.0.19, and 2.3.15 have been released, 8 Jan 2013 | https://rubyonrails.org/2013/1/8/Rails-3-2-11-3-1-10-3-0-19-and-2-3-15-have-been-released | 2026-11-12 | Confirmed |
| 72 | NVD, CVE-2013-0625 (detail page) | https://nvd.nist.gov/vuln/detail/CVE-2013-0625 | 2026-11-12 | Confirmed |
| 73 | NVD, CVE-2013-0640 (detail page) | https://nvd.nist.gov/vuln/detail/CVE-2013-0640 | 2026-11-12 | Confirmed |
| 74 | NVD, CVE-2013-2551 (detail page) | https://nvd.nist.gov/vuln/detail/CVE-2013-2551 | 2026-11-12 | Confirmed |
| 75 | Microsoft Security Bulletin MS13-038, 14 May 2013 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2013/ms13-038 | 2026-11-12 | Confirmed |
| 76 | CERT/CC, VU#237655, Microsoft Internet Explorer CGenericElement object use-after-free, 6 May 2013 | https://www.kb.cert.org/vuls/id/237655 | 2026-11-12 | Confirmed |
| 77 | NVD, CVE-2013-2094 (detail page) | https://nvd.nist.gov/vuln/detail/CVE-2013-2094 | 2026-11-12 | Confirmed |
| 78 | NVD, CVE-2013-2465 (detail page) | https://nvd.nist.gov/vuln/detail/CVE-2013-2465 | 2026-11-12 | Confirmed |
| 79 | Apache Struts, Security Bulletin S2-016 | https://cwiki.apache.org/confluence/display/WW/S2-016 | 2026-11-12 | Confirmed |
| 80 | US-CERT (CISA archive), TA13-207A, Risks of Using the Intelligent Platform Management Interface (IPMI), 26 Jul 2013 | https://www.cisa.gov/news-events/alerts/2013/07/26/risks-using-intelligent-platform-management-interface-ipmi | 2026-11-12 | Confirmed |
| 81 | Microsoft Security Bulletin MS13-080, 8 Oct 2013 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2013/ms13-080 | 2026-11-12 | Confirmed |
| 82 | FBI, GameOver Zeus Botnet Disrupted, 2 Jun 2014 | https://www.fbi.gov/news/stories/gameover-zeus-botnet-disrupted | 2026-11-12 | Confirmed |
| 83 | FBI, Evgeniy Mikhailovich Bogachev (wanted notice) | https://www.fbi.gov/wanted/cyber/evgeniy-mikhailovich-bogachev | 2026-11-12 | Confirmed (as charged) |
| 84 | FBI, Ransomware on the Rise | https://www.fbi.gov/news/stories/ransomware-on-the-rise | 2026-11-12 | Confirmed |
| 85 | Microsoft Security Bulletin MS14-002, 14 Jan 2014 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2014/ms14-002 | 2026-11-12 | Confirmed |
| 86 | Microsoft Security Bulletin MS13-098, 10 Dec 2013 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2013/ms13-098 | 2026-11-12 | Confirmed |
| 87 | Microsoft Security Bulletin MS13-106, 10 Dec 2013 (and the numbering series MS13-001 to MS13-107) | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2013/ms13-106 | 2026-11-12 | Confirmed (the bulletins); Inferred (the count) |
| 88 | KrebsOnSecurity, Sources: Target Investigating Data Breach, 18 Dec 2013 (updated 19 Dec) | https://krebsonsecurity.com/2013/12/sources-target-investigating-data-breach/ | 2026-11-12 | Reported |
| 89 | Yahoo, Form 8-K Exhibit 99.1, 14 Dec 2016 (SEC EDGAR) | `https://www.sec.gov/Archives/edgar/data/1011006/000119312516793106/d305610dex991.htm` | 2026-11-12 | Confirmed (the company's account) |
| 90 | MITRE ATT&CK, S0027 Zeroaccess | https://attack.mitre.org/software/S0027/ | 2026-11-12 | Confirmed |
| 91 | MITRE ATT&CK, S0016 P2P ZeuS | https://attack.mitre.org/software/S0016/ | 2026-11-12 | Confirmed |
| 92 | Verizon, Form 8-K Exhibit 99.1, 3 Oct 2017 (SEC EDGAR) | `https://www.sec.gov/Archives/edgar/data/732712/000073271217000003/a2017_10x3xoathxexhibitx991.htm` | 2026-11-12 | Confirmed (the company's account) |
| 93 | US Attorney, SDNY (archive), press release on the Ulbricht indictment, 4 Feb 2014 | https://www.justice.gov/archive/usao/nys/pressreleases/February14/RossUlbrichtIndictmentPR.php | 2026-11-12 | Confirmed (as charged) |
| 94 | US Attorney, District of New Jersey (archive), press release on the Auernheimer sentencing, 18 Mar 2013 | https://www.justice.gov/archive/usao/nj/Press/files/Auernheimer,%20Andrew%20Sentencing%20News%20Release.html | 2026-11-12 | Confirmed |
| 95 | ICS-CERT Monitor, October to December 2013 (CISA archive) | https://www.cisa.gov/sites/default/files/Monitors/ICS-CERT_Monitor_Oct-Dec2013.pdf | 2026-11-12 | Confirmed (the figures); Inferred (the ICS technique binding) |
| 96 | The White House (archive), Executive Order: Improving Critical Infrastructure Cybersecurity, 12 Feb 2013 | https://obamawhitehouse.archives.gov/the-press-office/2013/02/12/executive-order-improving-critical-infrastructure-cybersecurity | 2026-11-12 | Confirmed |
| 97 | NIST, History and Creation of the Framework | https://www.nist.gov/cyberframework/online-learning/history-and-creation-framework | 2026-11-12 | Confirmed |
| 98 | NIST, SP 800-53 Rev. 4, Security and Privacy Controls for Federal Information Systems and Organizations | https://csrc.nist.gov/pubs/sp/800/53/r4/upd3/final | 2026-11-12 | Confirmed |
| 99 | Federal Register (GovInfo), HIPAA Omnibus final rule, 78 FR 5566, 25 Jan 2013 | https://www.govinfo.gov/content/pkg/FR-2013-01-25/pdf/2013-01073.pdf | 2026-11-12 | Confirmed |
| 100 | European Commission, IP/13/13, European Cybercrime Centre, 9 Jan 2013 | https://ec.europa.eu/commission/presscorner/api/documents?reference=IP/13/13&language=en | 2026-11-12 | Confirmed |
| 101 | European Commission, IP/13/94, EU Cybersecurity plan, 7 Feb 2013 | https://ec.europa.eu/commission/presscorner/api/documents?reference=IP/13/94&language=en | 2026-11-12 | Confirmed |
| 102 | United Nations, A/68/98, Report of the Group of Governmental Experts, 24 Jun 2013 | https://documents.un.org/doc/undoc/gen/n13/371/66/pdf/n1337166.pdf | 2026-11-12 | Confirmed |
| 103 | NATO CCDCOE, Tallinn Manual | https://ccdcoe.org/research/tallinn-manual/ | 2026-11-12 | Confirmed |
| 104 | Microsoft (blog), Microsoft works with financial services industry leaders, law enforcement and others to disrupt massive financial cybercrime ring, 5 Jun 2013 | https://blogs.microsoft.com/blog/2013/06/05/microsoft-works-with-financial-services-industry-leaders-law-enforcement-and-others-to-disrupt-massive-financial-cybercrime-ring/ | 2026-11-12 | Confirmed |
| 105 | NIST, Framework Version 1.0 | https://www.nist.gov/cyberframework/framework-version-10 | 2026-11-12 | Confirmed |
| 106 | NIST, SP 800-40 Rev. 3, Guide to Enterprise Patch Management Technologies | https://csrc.nist.gov/pubs/sp/800/40/r3/final | 2026-11-12 | Confirmed |
| 107 | NIST, SP 800-83 Rev. 1, Guide to Malware Incident Prevention and Handling for Desktops and Laptops | https://csrc.nist.gov/pubs/sp/800/83/r1/final | 2026-11-12 | Confirmed |
| 108 | NIST, SP 800-63-2, Electronic Authentication Guideline | https://csrc.nist.gov/pubs/sp/800/63/2/final | 2026-11-12 | Confirmed |
| 109 | NIST, FIPS 186-4, Digital Signature Standard | https://csrc.nist.gov/pubs/fips/186-4/final | 2026-11-12 | Confirmed |
| 110 | ISO, ISO/IEC 27002:2013 | https://www.iso.org/standard/54533.html | 2026-11-12 | Confirmed |
| 111 | CVE (archived site), CVE-ID Syntax Change | https://www.cve.org/Resources/Media/Archives/OldWebsite/cve/identifiers/syntaxchange.html | 2026-11-12 | Confirmed |
| 112 | CVE (archived site), news archive for 2013 | https://www.cve.org/Resources/Media/Archives/OldWebsite/news/archives/2013/news.html | 2026-11-12 | Confirmed |
| 113 | MITRE, CWE news archive for 2013 | https://cwe.mitre.org/news/archives/news2013.html | 2026-11-12 | Confirmed |
| 114 | MITRE, CAPEC news archive for 2013 | https://capec.mitre.org/news/archives/news2013.html | 2026-11-12 | Confirmed |
| 115 | IETF (RFC Editor), RFC 6962, Certificate Transparency, Jun 2013 | https://www.rfc-editor.org/rfc/rfc6962 | 2026-11-12 | Confirmed |
| 116 | Microsoft Security Response Center, Heart of Blue Gold: Announcing New Bounty Programs, 19 Jun 2013 | https://www.microsoft.com/en-us/msrc/blog/2013/06/heart-of-blue-gold-announcing-new-bounty-programs | 2026-11-12 | Confirmed |
| 117 | Royal Holloway, Information Security Group, Lucky Thirteen | https://www.isg.rhul.ac.uk/tls/Lucky13.html | 2026-11-12 | Confirmed (the researchers' findings) |
| 118 | NVD, CVE-2013-0169 (API record) | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2013-0169` | 2026-11-12 | Confirmed |
| 119 | Royal Holloway, Information Security Group, On the Security of RC4 in TLS and WPA | https://www.isg.rhul.ac.uk/tls/ | 2026-11-12 | Confirmed (the researchers' findings) |
| 120 | NVD, CVE-2013-2566 (API record) | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2013-2566` | 2026-11-12 | Confirmed |
| 121 | Mandiant, APT1: Exposing One of China's Cyber Espionage Units (PDF, hosted by Google) | https://services.google.com/fh/files/misc/mandiant-apt1-report.pdf | 2026-11-12 | Confirmed (Mandiant's findings) |
| 122 | Target, Target Confirms Unauthorized Access to Payment Card Data in U.S. Stores, Dec 2013 | https://corporate.target.com/news-features/article/2013/12/target-confirms-unauthorized-access-to-payment-car | 2026-11-12 | Confirmed (the company's account) |
| 123 | TeamStarWolf library, ATT&CK and ICS data (`data/attack/`, `data/attack/ics/`, including `group_to_technique.jsonl`, `software_to_technique.jsonl`, `software_profiles.jsonl`, `groups.jsonl` and `technique_to_d3fend.jsonl`) | https://github.com/TeamStarWolf/TeamStarWolf/tree/main/data/attack | 2026-11-12; 2026-11-13 | Demonstrated |
| 124 | TeamStarWolf library, weakness data (`data/weaknesses/capec.jsonl`, `data/weaknesses/cwe.jsonl`) | https://github.com/TeamStarWolf/TeamStarWolf/tree/main/data/weaknesses | 2026-11-12; 2026-11-13 | Demonstrated |
| 125 | TeamStarWolf library, `mitre/` page tree (technique, group, software, campaign, CAPEC, D3FEND and mitigation pages) | https://github.com/TeamStarWolf/TeamStarWolf/tree/main/mitre | 2026-11-12; 2026-11-13 | Demonstrated |
| 126 | TeamStarWolf library, chronicle Navigator layers (`navigator/library-layers/chronicle-2016.json` and the later years) | https://github.com/TeamStarWolf/TeamStarWolf/tree/main/navigator/library-layers | 2026-11-12; 2026-11-13 | Demonstrated |
| 127 | TeamStarWolf library, case studies on main (home studies named in the text) | https://github.com/TeamStarWolf/TeamStarWolf/tree/main/case-studies | 2026-11-12; 2026-11-13 | Confirmed (for the fact that a study is the home and for the facts it carries from its own sources) |
| 128 | NVD, CVE-2013-3893 (API record) | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2013-3893` | 2026-11-13 | Confirmed |
| 129 | NVD, CVE-2013-3906 (API record) | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2013-3906` | 2026-11-13 | Confirmed |
| 130 | NVD, CVE-2013-3900 (API record) | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2013-3900` | 2026-11-13 | Confirmed |
| 131 | NVD, CVE-2013-2251 (API record) | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2013-2251` | 2026-11-13 | Confirmed |
| 132 | NVD, CVE-2013-0156 (API record) | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2013-0156` | 2026-11-13 | Confirmed |
| 133 | NVD, CVE-2013-5065 (API record) | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2013-5065` | 2026-11-13 | Confirmed |
| 134 | NVD, CVE-2013-4786 (API record) | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2013-4786` | 2026-11-13 | Confirmed |

*© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.*

*© The MITRE Corporation. Includes material from the Common Weakness Enumeration (CWE™), used under the CWE Terms of Use. https://cwe.mitre.org/*

*© The MITRE Corporation. Includes material from the Common Attack Pattern Enumeration and Classification (CAPEC™), used under the CAPEC Terms of Use. https://capec.mitre.org/*

*© The MITRE Corporation. Includes material from MITRE D3FEND™, used under the D3FEND Terms of Use. https://d3fend.mitre.org/*

*The terms for every MITRE dataset used here are recorded in [THIRD_PARTY_NOTICES.md](/THIRD_PARTY_NOTICES.md).*

## Related references

- [Notable Incidents](/NOTABLE_INCIDENTS.md), [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [CVE Reference](/CVE_REFERENCE.md)
- [Threat Intelligence](/THREAT_INTELLIGENCE_REFERENCE.md), [Browser Security](/BROWSER_SECURITY_REFERENCE.md), [Cryptography](/CRYPTOGRAPHY_REFERENCE.md), [Email Security](/EMAIL_SECURITY_REFERENCE.md), [Identity and Access Management](/IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md), [Web Application Security](/WEB_APPLICATION_SECURITY_REFERENCE.md), [Supply Chain Security](/SUPPLY_CHAIN_SECURITY_REFERENCE.md), [Ransomware Defense](/RANSOMWARE_DEFENSE_REFERENCE.md), [CWE Reference](/CWE_REFERENCE.md), [CAPEC Reference](/CAPEC_REFERENCE.md), [D3FEND Reference](/D3FEND_REFERENCE.md), [GRC and Compliance](/GRC_COMPLIANCE_REFERENCE.md), [Vulnerability Management](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [Incident Response](/INCIDENT_RESPONSE_REFERENCE.md), [ICS/OT Security](/ICS_OT_SECURITY_REFERENCE.md)
- Home studies: [China-attributed threat actors](/case-studies/THREAT_ACTORS_CHINA.md); [APT41](/case-studies/APT41_PUBLIC_RECORD.md); [North Korea-attributed threat actors](/case-studies/THREAT_ACTORS_NORTH_KOREA.md); [Iran-attributed threat actors](/case-studies/THREAT_ACTORS_IRAN.md); [Russia-attributed threat actors](/case-studies/THREAT_ACTORS_RUSSIA.md); [Other states' threat actors](/case-studies/THREAT_ACTORS_OTHER_STATES.md); [United States-attributed threat actors](/case-studies/THREAT_ACTORS_UNITED_STATES.md); [The Hacker and the State](/case-studies/HACKER_AND_THE_STATE_CASES.md); [The Zero-Day Market](/case-studies/ZERO_DAY_MARKET_EVENTS.md); [E-Commerce Threats](/case-studies/ECOMMERCE_THREATS.md); [Ransomware ecosystem](/case-studies/RANSOMWARE_ECOSYSTEM.md); [ICS attacks and advisories](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md); [Stuxnet](/case-studies/STUXNET.md); [Log4Shell](/case-studies/LOG4SHELL.md); [SolarWinds SUNBURST](/case-studies/SOLARWINDS_SUNBURST.md); [npm supply-chain attacks](/case-studies/NPM_SUPPLY_CHAIN_ATTACKS.md); [Hugging Face supply chain](/case-studies/HUGGING_FACE_SUPPLY_CHAIN.md)
- Series: [1993](/case-studies/CHRONICLE_1993.md), [1994](/case-studies/CHRONICLE_1994.md), [1995](/case-studies/CHRONICLE_1995.md), [1996](/case-studies/CHRONICLE_1996.md), [1997](/case-studies/CHRONICLE_1997.md), [1998](/case-studies/CHRONICLE_1998.md), [1999](/case-studies/CHRONICLE_1999.md), [2000](/case-studies/CHRONICLE_2000.md), [2001](/case-studies/CHRONICLE_2001.md), [2002](/case-studies/CHRONICLE_2002.md), [2003](/case-studies/CHRONICLE_2003.md), [2004](/case-studies/CHRONICLE_2004.md), [2005](/case-studies/CHRONICLE_2005.md), [2006](/case-studies/CHRONICLE_2006.md), [2007](/case-studies/CHRONICLE_2007.md), [2010](/case-studies/CHRONICLE_2010.md), [2011](/case-studies/CHRONICLE_2011.md), [2012](/case-studies/CHRONICLE_2012.md), [2016](/case-studies/CHRONICLE_2016.md), [2017](/case-studies/CHRONICLE_2017.md), [2018](/case-studies/CHRONICLE_2018.md), [2019](/case-studies/CHRONICLE_2019.md), [2020](/case-studies/CHRONICLE_2020.md), [2021](/case-studies/CHRONICLE_2021.md), [2022](/case-studies/CHRONICLE_2022.md), [2023](/case-studies/CHRONICLE_2023.md), [2024](/case-studies/CHRONICLE_2024.md), [2025](/case-studies/CHRONICLE_2025.md), [2026](/case-studies/CHRONICLE_2026.md)
- Techniques: [T1189 Drive-by Compromise](/mitre/techniques/T1189.md), [T1203 Exploitation for Client Execution](/mitre/techniques/T1203.md), [T1566.001 Spearphishing Attachment](/mitre/techniques/T1566-001.md), [T1190 Exploit Public-Facing Application](/mitre/techniques/T1190.md), [T1195.002 Compromise Software Supply Chain](/mitre/techniques/T1195-002.md), [T1199 Trusted Relationship](/mitre/techniques/T1199.md), [T1068 Exploitation for Privilege Escalation](/mitre/techniques/T1068.md), [T1553.002 Code Signing](/mitre/techniques/T1553-002.md), [T1003.001 LSASS Memory](/mitre/techniques/T1003-001.md), [T1550.002 Pass the Hash](/mitre/techniques/T1550-002.md), [T1056.001 Keylogging](/mitre/techniques/T1056-001.md), [T1110.001 Password Guessing](/mitre/techniques/T1110-001.md), [T1102.001 Dead Drop Resolver](/mitre/techniques/T1102-001.md), [T1498.002 Reflection Amplification](/mitre/techniques/T1498-002.md), [T1486 Data Encrypted for Impact](/mitre/techniques/T1486.md); the full list is in the Part 11 table
- CAPEC: [CAPEC-49](/mitre/capec/CAPEC-49.md), [CAPEC-66](/mitre/capec/CAPEC-66.md), [CAPEC-68](/mitre/capec/CAPEC-68.md), [CAPEC-163](/mitre/capec/CAPEC-163.md), [CAPEC-206](/mitre/capec/CAPEC-206.md), [CAPEC-473](/mitre/capec/CAPEC-473.md), [CAPEC-490](/mitre/capec/CAPEC-490.md), [CAPEC-552](/mitre/capec/CAPEC-552.md), [CAPEC-555](/mitre/capec/CAPEC-555.md), [CAPEC-560](/mitre/capec/CAPEC-560.md), [CAPEC-568](/mitre/capec/CAPEC-568.md), [CAPEC-644](/mitre/capec/CAPEC-644.md)
- Groups, software and campaigns: APT1 [G0006](/mitre/groups/G0006.md); Winnti Group [G0044](/mitre/groups/G0044.md); Kimsuky [G0094](/mitre/groups/G0094.md); Molerats [G0021](/mitre/groups/G0021.md); APT29 [G0016](/mitre/groups/G0016.md); Lazarus Group [G0032](/mitre/groups/G0032.md); Ke3chang [G0004](/mitre/groups/G0004.md); Gamaredon Group [G0047](/mitre/groups/G0047.md); Carbanak [G0008](/mitre/groups/G0008.md); NetTraveler [S0033](/mitre/software/S0033.md); MiniDuke [S0051](/mitre/software/S0051.md); Zeroaccess [S0027](/mitre/software/S0027.md); Wiper [S0041](/mitre/software/S0041.md); PlugX [S0013](/mitre/software/S0013.md); P2P ZeuS [S0016](/mitre/software/S0016.md); FinFisher [S0182](/mitre/software/S0182.md); Operation Ghost [C0023](/mitre/campaigns/C0023.md)
- [Navigator layers](/navigator/index.md), including this study's layer, [chronicle-2013.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/chronicle-2013.json)
