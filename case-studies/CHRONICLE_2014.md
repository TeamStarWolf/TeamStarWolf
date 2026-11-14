# The Year 2014 in Intrusions: A Dated Record

*A TeamStarWolf case study. Published 13 November 2026; every source checked as of that date.*

[All case studies](/case-studies/README.md) · Related: [Notable Incidents](/NOTABLE_INCIDENTS.md), [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [CVE Reference](/CVE_REFERENCE.md), [Threat Intelligence](/THREAT_INTELLIGENCE_REFERENCE.md), [Cryptography](/CRYPTOGRAPHY_REFERENCE.md), [Web Application Security](/WEB_APPLICATION_SECURITY_REFERENCE.md), [GRC and Compliance](/GRC_COMPLIANCE_REFERENCE.md), [Incident Response](/INCIDENT_RESPONSE_REFERENCE.md), [Vulnerability Management](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [Ransomware Defense](/RANSOMWARE_DEFENSE_REFERENCE.md), [ICS/OT Security](/ICS_OT_SECURITY_REFERENCE.md) · Home studies for events summarized here: [E-Commerce Threats](/case-studies/ECOMMERCE_THREATS.md) (Target, Backoff and Home Depot), [China-attributed threat actors](/case-studies/THREAT_ACTORS_CHINA.md) (the Unit 61398 indictment), [The Hacker and the State](/case-studies/HACKER_AND_THE_STATE_CASES.md) (the indictment, the OPM intrusions, Regin and Sony), [North Korea-attributed threat actors](/case-studies/THREAT_ACTORS_NORTH_KOREA.md) (Sony Pictures), [Russia-attributed threat actors](/case-studies/THREAT_ACTORS_RUSSIA.md) (Dragonfly, Turla, APT28), [Sandworm Operations](/case-studies/SANDWORM_OPERATIONS.md) (BlackEnergy and CVE-2014-4114), [Iran-attributed threat actors](/case-studies/THREAT_ACTORS_IRAN.md) (Las Vegas Sands, Flying Kitten, Newscaster, Cleaver), [Other states' threat actors](/case-studies/THREAT_ACTORS_OTHER_STATES.md) (Darkhotel and Machete), [NSA and CIA tool leaks](/case-studies/NSA_CIA_TOOL_LEAKS.md) (the April 2014 statement on vulnerability disclosure), [Cybercrime and Hacktivism in Four Books](/case-studies/CYBERCRIME_FOUR_BOOKS.md) (the Monsegur sentence and the Prolexic purchase), [The Year 2016 in Intrusions](/case-studies/CHRONICLE_2016.md) (the Yahoo theft of late 2014 and the 2016 designation of the GameOver Zeus administrator) · Series: [The Year 2012 in Intrusions](/case-studies/CHRONICLE_2012.md), [The Year 2016 in Intrusions](/case-studies/CHRONICLE_2016.md) and the other years in the [case studies index](/case-studies/README.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Threat intelligence analysts, security historians, vulnerability management, payment-card, ICS and policy teams and anyone who wants the history behind current threats

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Beginner to intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 77 min (17,702 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want a dated record of the intrusions of 2014, you need Heartbleed, Shellshock and POODLE side by side with the exploited Internet Explorer, Kerberos and Group Policy flaws, the point-of-sale breaches, the Unit 61398 indictment, Sony Pictures, Havex and the year's espionage reports, the takedowns that went to court, the laws and standards that followed, or you want the defender lessons that still apply

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [Part 2: the shared-code vulnerabilities](#part-2-the-shared-code-vulnerabilities), [Part 7: breaches and data loss](#part-7-breaches-and-data-loss)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Notable Incidents](/NOTABLE_INCIDENTS.md), [E-Commerce Threats](/case-studies/ECOMMERCE_THREATS.md), [Sandworm: The Operations in the Public Record](/case-studies/SANDWORM_OPERATIONS.md), [The Year 2012 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2012.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive summary

The year's defining failures were in code that nearly everyone shared. On 7 April OpenSSL disclosed CVE-2014-0160, Heartbleed: a missing bounds check in the TLS heartbeat extension let a remote attacker read up to 64k of a server's memory, repeatedly, exposing private keys and credentials (Confirmed [11][12][14]). In June a second OpenSSL flaw let a man-in-the-middle force weak keying material between a vulnerable client and a vulnerable server (Confirmed [37]). On 24 September NVD published Shellshock, CVE-2014-6271, in GNU Bash, reachable through web CGI scripts, the OpenSSH ForceCommand restriction and DHCP clients, and US-CERT listed five follow-on CVEs because the first fixes were incomplete (Confirmed [28][29]). On 14 October Google disclosed POODLE, a design flaw in SSL 3.0 that no patch could repair, and the browser makers began removing the protocol (Confirmed [31][32][34]). The same year brought institutional changes: Google's Project Zero (July), whose announcement cites Heartbleed, the LibreSSL fork, Let's Encrypt (announced in November) and an IETF statement that pervasive monitoring is an attack (Confirmed [112][113][111][109]; Inferred for any link between them).

Retail card theft ran all year. Target's annual report put the late-2013 breach at about 40 million card accounts plus contact data for up to 70 million people, and a Senate staff report in March, built from media reports and expert analyses, described a foothold through an HVAC vendor's network access (Confirmed [1][2]; Reported for the vendor detail [2]). Neiman Marcus, Michaels, Home Depot (about 56 million cards), Kmart and Staples followed with point-of-sale malware disclosures in their own filings, SUPERVALU with a card-network intrusion, and US-CERT's Backoff alert said more than 1,000 US businesses were affected by malware deployed after attackers brute-forced remote-desktop logins (Confirmed [82][83][81][78][80][84][85]). Other breaches lost other data: eBay's employee credentials opened a customer database, JPMorgan Chase lost contact data on about 76 million households and 7 million small businesses, and Community Health Systems lost identity data, including Social Security numbers, on about 4.5 million patients (Confirmed [73][76][49]). MtGox, a bitcoin exchange, filed for civil rehabilitation in Tokyo on 28 February (Confirmed [7]).

Governments named states. On 19 May the United States announced the indictment of five officers of PLA Unit 61398 on 31 counts for intrusions into US nuclear, metals and solar companies and a labor union, which the FBI called the first criminal charges filed against known state actors for hacking (Confirmed [42][43]). On 19 December the FBI said the North Korean government was responsible for the destructive attack on Sony Pictures Entertainment, which rendered thousands of computers inoperable, and US-CERT described the wiper toolset without naming the victim or the actor (Confirmed [70][71]). Most private reports that year named no state: Kaspersky's Careto, Regin and Darkhotel reports, Symantec's Dragonfly report and F-Secure's BlackEnergy paper all stopped short, and the state attributions that ATT&CK carries now came later (Confirmed [59][63][61][52][55]; Inferred for the reading [63]).

Industrial systems became a visible target. ICS-CERT reported the Havex campaign, which used phishing, watering holes and trojanized installers on at least three ICS vendor websites, and a BlackEnergy campaign against internet-connected human-machine interfaces running since at least 2011; ICS-CERT's pages added a Russian nation-state attribution only in their 20 July 2021 updates; Dragonfly as a group was tied to the Russian government earlier, in 2018 (see [Russia-attributed threat actors](/case-studies/THREAT_ACTORS_RUSSIA.md)) (Confirmed [50][51][54][126]). Germany's BSI reported a targeted attack on a steel mill in which a blast furnace could not be shut down in a controlled way, causing massive damage (Confirmed [94]).

Law and standards moved at both ends of the year. NIST published Cybersecurity Framework 1.0 on 12 February, and on 18 December three US cybersecurity laws were enacted on the same day: the Federal Information Security Modernization Act, the Cybersecurity Enhancement Act and the National Cybersecurity Protection Act (Confirmed [96][104][105][106]). Europe's highest court struck down the Data Retention Directive in April and recognized a right to seek removal of name-based search results in May, and the US Supreme Court required a warrant for phone searches incident to arrest in June (Confirmed [98][99][100]).

This study records the year by date. It is built from sources opened on 12 November 2026 and from checks of the library's data run on 12 and 13 November 2026, and is checked as of 13 November 2026.

### Key facts at a glance

| Field | Value |
|---|---|
| Period | 1 January to 31 December 2014, plus the records that open, close or explain a 2014 event: Regin samples dated to 2003, the 2013 retail breaches disclosed in 2014, the 2015 Staples filing, the 2015 RFCs on SSL 3.0, ATT&CK's public release in May 2015, Yahoo's 2016 filing, the 2021 ICS-CERT attribution updates and KEV additions from 2021 to 2025 |
| Shared-code flaws | Heartbleed CVE-2014-0160 (7 Apr); CCS injection CVE-2014-0224 (5 Jun); Shellshock CVE-2014-6271 and five follow-ons (24 to 25 Sep); POODLE CVE-2014-3566 (14 Oct); Apple's CVE-2014-1266 (22 Feb, NVD) (Confirmed [11][37][28][29][31][6]) |
| Exploited in 2014 per the vendor, US-CERT or NVD | IE CVE-2014-0322 (Feb); IE CVE-2014-1776 (Apr to May); GPP CVE-2014-1812 (May); OLE CVE-2014-4114 (Jun to Oct); Drupal CVE-2014-3704 (Oct, within hours); Kerberos CVE-2014-6324 (Nov); NTP CVE-2013-5211 in DDoS (Jan) (Confirmed [5][16][19][21][39][25][4]) |
| KEV tail | 34 CVE-2014 entries in catalog 2026.11.10, all added 2021-11-03 or later; CVE-2014-1812 the only one flagged for known ransomware use; CVE-2014-6278 added 2025-10-02 (Confirmed [27][19][29]) |
| Retail card breaches | Target (2013 window, about 40 million cards); Neiman Marcus (about 350,000); Michaels (about 2.6 million) and Aaron Brothers (about 400,000); SUPERVALU (180 stores and 29 franchised stores); Home Depot (about 56 million); Kmart; Staples (about 1.16 million) (Confirmed [1][82][83][81][78][80][84]) |
| Other breaches | eBay (Feb to Mar); CHS (Apr and Jun, about 4.5 million patients); celebrity Apple accounts (Sep); JPMorgan Chase (76 million households, 7 million small businesses); Yahoo (late 2014, at least 500 million accounts, disclosed 2016) (Confirmed [73][49][75][76][86]) |
| State and espionage reports | Careto (10 Feb); Flying Kitten (13 May); Unit 61398 indictment (1 May, announced 19 May); Putter Panda (9 Jun); Havex (25 to 27 Jun) and Dragonfly (30 Jun); Epic Turla (7 Aug); El Machete (20 Aug); Group 72 (14 Oct); BlackEnergy HMIs (8 Oct); Darkhotel (10 Nov); Regin (24 Nov); Sony and the FBI's attribution (late Nov; 19 Dec) (Confirmed [59][66][43][42][44][50][52][57][60][46][54][61][63][70]) |
| Crimeware and takedowns | Blackshades (19 May); GameOver Zeus and CryptoLocker (2 Jun); Backoff (31 Jul); No-IP and njRAT (30 Jun); crypto ransomware alert (22 Oct); Silk Road 2.0 (6 Nov) (Confirmed [87][88][85][92][91][93]) |
| Industrial systems | Havex trojanized vendor installers; BlackEnergy on HMIs since 2011; German steel mill blast furnace; ICS-CERT's 245 FY2014 incidents, 79 in energy (Confirmed [51][54][94][95]) |
| Policy and standards | PPD-28 (17 Jan); CSF 1.0 (12 Feb); CJEU Digital Rights Ireland (8 Apr) and Google Spain (13 May); SEC OCIE sweep (15 Apr); Cyber Essentials (Apr to Jun); Riley v. California (25 Jun); NATO Wales (5 Sep); EO 13681 (17 Oct); three US laws (18 Dec); CVE syntax change (1 Jan) (Confirmed [97][96][98][99][101][108][100][107][103][104][105][106][114]) |
| This study's MITRE binding | 45 ATT&CK Enterprise techniques in 56 technique-tactic entries: 31 listed by ATT&CK for an object tied to a 2014 report or event, 10 described by a primary and assigned here, one supported only by a Reported source and three Inferred; 14 ATT&CK for ICS techniques; CWE ids from NVD; CAPEC and D3FEND pairings from the library's data; one Enterprise and one ICS Navigator layer (Part 12) |

### Key findings

- **The shared libraries failed in public.** OpenSSL, Bash and SSL 3.0 were each in so much software that their flaws got names, and US-CERT told Heartbleed's victims to regenerate keys, not only to patch, while the first Shellshock fixes were incomplete (Confirmed [12][29][34]).
- **The branded bugs and the exploited bugs were not the same list.** KEV added Heartbleed and Shellshock only in 2022 and never added POODLE, while Microsoft's GPP and Kerberos flaws were under targeted attack when the fixes shipped (Confirmed [13][28][35][19][25]).
- **Point-of-sale malware was an industry, not an incident.** Seven retailers' own filings describe card-data intrusions in 2013 or 2014, six of them naming malware, and the Secret Service estimated more than 1,000 US businesses were affected by Backoff alone (Confirmed [1][82][83][81][78][80][84][85]).
- **Third-party access was the recurring door.** Home Depot's attackers used a vendor's user name and password, and the Senate report, relying on press accounts, says Target's came through an HVAC vendor (Confirmed [79]; Reported [2]).
- **State officers were charged with hacking for the first time.** The Unit 61398 indictment named five officers, six victims and 31 counts, and the FBI called it the first criminal case against known state actors for hacking (Confirmed [42][43]).
- **Destructive malware hit a major US company, and the US named the state within a month.** The Sony attack used a wiper that overwrote drives and master boot records, and the FBI made a public state attribution within a month (Confirmed [70][71]).
- **Most 2014 private reports named no state.** Careto, Regin, Darkhotel, Dragonfly and Quedagh were described in detail and attributed later, if at all (Confirmed [59][63][61][52][55]).
- **Industrial systems were reached through the IT side.** Havex came through vendor websites and phishing, BlackEnergy through internet-facing HMIs, and the steel mill through spear-phishing into the office network (Confirmed [51][54][94]).
- **Ransomware demands were small, and its variants were proliferating.** TA14-295A put typical demands at USD 100 to 300, sometimes in bitcoin, and the GameOver Zeus operation also seized CryptoLocker's servers (Confirmed [91][88]).
- **No 2014 event had a contemporaneous ATT&CK mapping.** ATT&CK was released publicly in May 2015, so every technique id here is assigned in hindsight (Confirmed [117]; Inferred for the binding).

### Top recommendations

1. **Keep an inventory of shared libraries, not only products.** Heartbleed sat in OpenSSL 1.0.1 through 1.0.1f, and finding it required knowing which services linked that library (Confirmed [11]; Inferred for the advice).
2. **Treat key material as exposed after a memory-disclosure flaw.** US-CERT and CERT/CC advised regenerating and revoking keys after patching Heartbleed, and recommended Perfect Forward Secrecy (Confirmed [12][14]).
3. **Retire protocols that cannot be fixed.** TA14-290A said SSL 3.0 should be disabled, and OpenSSL, Google and Mozilla shipped fallback protection and removal (Confirmed [34][33][31][32]).
4. **Restore from a known-good backup when exploitation came first.** Drupal told owners to assume compromise unless patched before 15 October 23:00 UTC, because patching does not remove backdoors (Confirmed [39]).
5. **Put vendor and remote access behind multi-factor authentication and separate networks.** Backoff came through brute-forced remote desktop, and Home Depot's attackers through a vendor's credentials (Confirmed [85][79]).
6. **Remove stored passwords from Group Policy.** MS14-025 stopped new GPP passwords but did not remove existing ones (Confirmed [19]).
7. **Patch Kerberos domain controllers first.** MS14-068 let an authenticated domain user obtain a ticket accepted as domain admin and was under limited, targeted attack at release (Confirmed [25]).
8. **Keep offline backups and a destructive-malware plan.** TA14-353A described tools that overwrite drives and master boot records, and TA14-295A described file-encrypting ransomware (Confirmed [71][91]).
9. **Take HMIs and control-system management off the internet.** The BlackEnergy campaign reached internet-connected HMIs, in GE Cimplicity's case through CVE-2014-0751, which was exploited from at least January 2012 (Confirmed [54]).
10. **Verify vendor software before installing it in control networks.** Havex was spread through trojanized installers on ICS vendor sites (Confirmed [51]).
11. **Do not read KEV dates as event dates.** Heartbleed was disclosed in April 2014 and entered KEV in May 2022 (Confirmed [13]).

## Scope and method

This study covers intrusions, malware, denial of service, vulnerabilities, data breaches, crimeware and takedowns, prosecutions, state and espionage operations, industrial-control incidents and advisories, and regulation, standards and policy dated to 2014, plus the later records that open, close or explain a 2014 event. It follows the method of the [case studies collection](/case-studies/README.md): primary sources first, every claim graded, and numbers given as the source states them. Every external source was opened on 12 November 2026, as the Sources table shows, and the library data checks were run on 12 and 13 November 2026. The Intelligence Hub's 2014 history shards (171 US-CERT alert rows and 95 ICS advisory rows) served as an index of dated rows; each fact cited here comes from the primary that row points to (Demonstrated [120]).

| Grade | Meaning in this study |
|---|---|
| Confirmed | The primary record was opened and states the fact: a vendor advisory, bulletin or blog, a company's own statement or SEC filing, a CERT/CC, US-CERT, ICS-CERT or CISA record, a CVE or NVD record, the KEV catalog, an FBI record, a court opinion or press release, a public law, a White House, Federal Register, EU, NATO or UK government record, a NIST, IETF or MITRE record, a researchers' or vendor's report stated as its own finding, a live ATT&CK page or the library's ATT&CK data for what ATT&CK records, or a library study, only for the fact that it is the home for an event |
| Reported | Only a secondary source supports the fact, a source relays someone else's claim without the original being opened here, or a company states its own belief about who attacked it: the Senate report's reliance on press accounts for Target's point of entry, eWeek on iSIGHT's Newscaster report, ATT&CK's pages where they rest on reports not opened here (Cleaver, APT3's 2014 exploit, Kimsuky and KHNP, the APT28 indictment), Codenomicon's account of Heartbleed's discovery, and the attributions in the CHS and Yahoo filings. The source is named in the text |
| Demonstrated | A check this study ran itself and saw the result: id, name, tactic, CAPEC, D3FEND and page checks in the library's data files and `mitre/` tree, and the count of rows in the Intelligence Hub's 2014 history |
| Inferred | The study's own reading, labelled where it appears. Every ATT&CK, CAPEC and D3FEND id bound to a 2014 event is Inferred as to the binding unless ATT&CK lists it for the object, and so is every CWE that NVD does not list |

Charges, complaints and indictments are allegations; where this study cites one, the record confirms that the charge was made, not that it was proven. Company statements are the company's own account, and vendor and researcher attributions are those authors' assessments, not government findings.

Limits a reader should know:

- **CVE existed; ATT&CK and KEV did not.** Every 2014 product flaw here carries a CVE id, and the CVE program changed its id syntax on 1 January 2014 so a year could hold more than 9,999 ids (Confirmed [114]). No 2014 record carries an ATT&CK technique id. MITRE built its first ATT&CK model in September 2013 inside its own research environment and released it publicly in May 2015 with 96 techniques under nine tactics, so every technique id in Part 12 is assigned in hindsight (Confirmed [117]; Inferred for the binding). KEV's 34 CVE-2014 entries were added from November 2021 on (Confirmed [27]).
- **Some events have no ATT&CK object.** Careto, CryptoLocker, BlackShades, Backoff, the German steel mill and the 2014 retail breaches have no object in the library's ATT&CK data (Confirmed [59]; Demonstrated [121]).
- **Some primaries could not be opened, and their facts come from another primary.** Department of Justice press releases sat behind a bot challenge, so the matching FBI pages were used; Drupal's SA-CORE-2014-005 page would not load, so NVD and Drupal's PSA-2014-003 were used (Confirmed [42][88][87][38][39]).
- **What was not checked.** No primary was opened, or the page would not open, for: FireEye's Operation Clandestine Fox post, its Saffron Rose report and its October 2014 APT28 report; iSIGHT's Newscaster and Sandworm reports; Cylance's Operation Cleaver report; Novetta's Operation SMN and Operation Blockbuster reports; Apple's own bulletin for CVE-2014-1266; press attributions of Regin to Five Eyes agencies; counts of Heartbleed exploitation in 2014; the Linux Foundation's Core Infrastructure Initiative announcement; the dates of the 2014 OPM intrusions in the House report (an image-only PDF); the 2018 GRU indictment's text; P.F. Chang's, UPS Store, Dairy Queen, Goodwill, the State Department and White House unclassified network intrusions, the KHNP leaks, Code Spaces, USPS, the Christmas console-network DDoS and the SpyEye plea; FTC actions on Fandango, Credit Karma, Snapchat and Wyndham; HHS's NewYork-Presbyterian resolution; the FDA's October 2014 premarket guidance; and Europol's Operation Onymous release. They are left out or marked "not checked" where they touch a verified fact. Their absence here is not evidence that nothing happened.

## Part 1: the year as a dated timeline

One row per event or report. The date is the event date where the source gives one, otherwise the publication date. Rows marked "frame" or "boundary" open or close a 2014 event.

| Date | Event | Thread | Sector | Grade | Sources |
|---|---|---|---|---|---|
| 2003 (frame) | Regin samples timestamped back to 2003 | Espionage | Telecom; government | Confirmed (vendor's finding) | [63][65] |
| 2007 (frame) | Careto running since at least 2007; Putter Panda activity dates to 2007; BlackEnergy in criminal and APT use since at least 2007 | Espionage | Government; defense; aerospace | Confirmed (vendors' findings) | [59][44][56] |
| 2010 to 2013 (frame) | El Machete begins (2010, renewed 2012); most Darkhotel hotel activity (Aug 2010 to 2013) | Espionage | Government; executives | Confirmed (vendor's finding) | [60][61] |
| 2011 (frame) | Dragonfly active since at least 2011; BlackEnergy HMI campaign since at least 2011; GameOver Zeus first identified (Sep) | Espionage; ICS; Crimeware | Energy; finance | Confirmed | [52][54][90] |
| 2012-01 (frame) | GE Cimplicity CVE-2014-0751 exploited since at least January 2012 | ICS | Energy | Confirmed | [54] |
| 2013 (frame) | Dragonfly shifts to US and European energy firms (early 2013); Michaels (8 May 2013 to 27 Jan 2014), Aaron Brothers (26 Jun 2013 to 27 Feb 2014) and Neiman Marcus (16 Jul to 30 Oct 2013) card windows; Backoff variants from Oct 2013; Target's window (27 Nov to 15 Dec 2013). Home for Target: [E-Commerce Threats](/case-studies/ECOMMERCE_THREATS.md) | Espionage; Breach | Energy; Retail | Confirmed | [52][83][82][85][1] |
| 2014-01-01 | CVE id syntax change takes effect | Standards | Cross-sector | Confirmed | [114] |
| 2014-01-02 | US-CERT TA14-002A, Malware Targeting Point of Sale Systems; NVD publishes CVE-2013-5211 (ntpd monlist) | Crimeware; Vulnerability | Retail; Internet | Confirmed | [3][4] |
| 2014-01 | Neiman Marcus finds malware that tried to collect card data in 2013 | Breach | Retail | Confirmed | [82] |
| 2014-01-13 | US-CERT alert on NTP amplification DDoS using CVE-2013-5211 | DDoS | Internet | Confirmed | [4] |
| 2014-01-17 | PPD-28, Signals Intelligence Activities | Policy | Intelligence | Confirmed | [97] |
| 2014-01 (mid) | CrowdStrike begins tracking FLYING KITTEN | Espionage | Defense; dissidents | Confirmed (vendor's finding) | [66] |
| 2014-02-06 | CAPEC 2.3 | Standards | Software | Confirmed | [116] |
| 2014-02-10 | Kaspersky publishes Careto (The Mask) | Espionage | Government; diplomatic; energy; activists | Confirmed (vendor's finding) | [59] |
| 2014-02 | A cryptographer discloses an intrusion later tied to Regin; attack on Las Vegas Sands, attributed to Iran by the DNI in February 2015 (home: [Iran-attributed threat actors](/case-studies/THREAT_ACTORS_IRAN.md)); ASUS router intrusions (home: [2016 chronicle](/case-studies/CHRONICLE_2016.md)) | Espionage; Intrusion; Consumer devices | Research; Gaming; Consumer | Confirmed (Regin cryptographer); Reported (Sands attack and attribution) | [63][126] |
| 2014-02-12 | NIST Cybersecurity Framework 1.0 | Policy | Critical infrastructure | Confirmed | [96] |
| 2014-02-14 | US-CERT: IE 9 and 10 use-after-free CVE-2014-0322 actively exploited | Vulnerability | Cross-sector | Confirmed | [5] |
| 2014-02-18 | Akamai completes its Prolexic purchase (home: [Cybercrime and Hacktivism in Four Books](/case-studies/CYBERCRIME_FOUR_BOOKS.md)) | Industry | DDoS protection | Confirmed | [126] |
| 2014-02-19 | CWE 2.6 | Standards | Software | Confirmed | [115] |
| 2014-02-22 | NVD publishes CVE-2014-1266, Apple Secure Transport signature check | Vulnerability | Technology | Confirmed | [6] |
| 2014-02 to 2014-03 | eBay database compromised through employee credentials | Breach | E-commerce | Confirmed | [73] |
| 2014-02-28 | MtGox applies for civil rehabilitation; Tokyo District Court accepts the application the same day | Crime and courts | Crypto exchange | Confirmed | [7][8] |
| 2014-03-10 | US-CERT TA14-069A on the end of Windows XP and Office 2003 support | Vulnerability management | Cross-sector | Confirmed | [9] |
| 2014-03-12 | Neiman Marcus 10-Q: about 350,000 cards could have been collected | Breach | Retail | Confirmed | [82] |
| 2014-03-14 | Target files its FY2013 10-K; MtGox files a US Chapter 15 application | Breach; Courts | Retail; Crypto exchange | Confirmed | [1][8] |
| 2014-03-20 | US-CERT notice to OPM of the 2014 intrusion (home: [The Hacker and the State](/case-studies/HACKER_AND_THE_STATE_CASES.md)); MtGox notice on bitcoin balance | Espionage; Courts | Government; Crypto exchange | Confirmed | [126][8] |
| 2014-03-26 | Senate Commerce majority staff, A Kill Chain Analysis of the 2013 Target Data Breach; SEC Cybersecurity Roundtable | Breach; Policy | Retail; Finance | Confirmed; Reported (vendor detail) | [2][101] |
| 2014-04 and 2014-06 | Community Health Systems attacked | Breach | Healthcare | Confirmed | [49] |
| 2014-04 onward | Malware in Home Depot's payment systems (April to September) | Breach | Retail | Confirmed | [77][78] |
| 2014-04-07 | OpenSSL discloses Heartbleed, CVE-2014-0160; NVD publishes it; UK Cyber Essentials overview first published | Vulnerability; Policy | Internet; Cross-sector | Confirmed | [11][13][108] |
| 2014-04-08 | US-CERT TA14-098A and CERT/CC VU#720951 on Heartbleed; Windows XP extended support ends; CJEU invalidates the Data Retention Directive | Vulnerability; Policy | Internet; Cross-sector | Confirmed | [12][14][10][98] |
| 2014-04-10 | CAPEC 2.4 | Standards | Software | Confirmed | [116] |
| 2014-04-15 | SEC OCIE risk alert: cybersecurity examinations of more than 50 broker-dealers and advisers | Policy | Finance | Confirmed | [101] |
| 2014-04-24 | MtGox bankruptcy proceedings commence | Crime and courts | Crypto exchange | Confirmed | [8] |
| 2014-04-26 | Microsoft Security Advisory 2963983 for IE CVE-2014-1776, crediting FireEye; FireEye's Clandestine Fox post, as ATT&CK cites it | Vulnerability; Espionage | Cross-sector | Confirmed; Reported (the APT3 link) | [17][48] |
| 2014-04-28 | US-CERT: active exploitation of IE 6 to 11 CVE-2014-1776; Michael Daniel's statement on the vulnerability-disclosure process (home: [NSA and CIA tool leaks](/case-studies/NSA_CIA_TOOL_LEAKS.md)) | Vulnerability; Policy | Cross-sector | Confirmed | [16][126] |
| 2014-04-29 | Michaels 10-K: about 2.6 million Michaels and 400,000 Aaron Brothers cards | Breach | Retail | Confirmed | [83] |
| 2014-05 | RFC 7258 (BCP 188), Pervasive Monitoring Is an Attack | Standards | Internet | Confirmed | [109] |
| 2014-05-01 | Grand jury indicts five Unit 61398 officers on 31 counts; MS14-021, out of band, fixes CVE-2014-1776, including for Windows XP | Courts; Vulnerability | Nuclear, metals, solar, labor; Cross-sector | Confirmed (as charged) | [43][18] |
| 2014-05-07 | CAPEC 2.5 | Standards | Software | Confirmed | [116] |
| 2014-05-13 | MS14-025 (Group Policy Preferences passwords, CVE-2014-1812); CJEU Google Spain judgment; CrowdStrike FLYING KITTEN and FireEye Saffron Rose | Vulnerability; Policy; Espionage | Cross-sector; Internet; Defense | Confirmed | [19][99][66] |
| 2014-05-19 | Unit 61398 indictment announced; Blackshades takedown; W.D. Pa. indictment of Bogachev in his true name | Courts; Takedown | Nuclear, metals, solar, labor; Consumer; Finance | Confirmed (as charged) | [42][87][89] |
| 2014-05-21 to 2014-05-22 | eBay asks users to change passwords; 8-K exhibit filed | Breach | E-commerce | Confirmed | [73][74] |
| 2014-05-27 | Monsegur sentenced (home: [Cybercrime and Hacktivism in Four Books](/case-studies/CYBERCRIME_FOUR_BOOKS.md)) | Courts | Hacktivism | Confirmed | [126] |
| 2014-05-28 | eWeek reports iSIGHT's Newscaster findings | Espionage | Defense; government | Reported | [67] |
| 2014-05-30 | District of Nebraska complaint ties "lucky12345" to Bogachev | Courts | Finance | Confirmed (as charged) | [89] |
| 2014-06 | Emotet first emerges, targeting the financial sector, per ATT&CK | Crimeware | Finance | Confirmed | [121] |
| 2014-06-02 | GameOver Zeus and CryptoLocker disruption; US-CERT TA14-150A | Takedown | Finance; Consumer | Confirmed | [88][90] |
| 2014-06-05 | OpenSSL CCS injection, CVE-2014-0224; Cyber Essentials requirements published | Vulnerability; Policy | Internet; Cross-sector | Confirmed | [37][108] |
| 2014-06-09 | CrowdStrike's PUTTER PANDA report on PLA Unit 61486 | Espionage | Defense; satellite; aerospace | Confirmed (vendor's finding) | [44][45] |
| 2014-06-10 | SEC Commissioner Aguilar on boards and cyber risk | Policy | Finance | Confirmed | [102] |
| 2014-06-18 | US recognition order in the MtGox Chapter 15 case | Courts | Crypto exchange | Confirmed | [8] |
| 2014-06-22 to 2014-07-17 | SUPERVALU card window | Breach | Retail | Confirmed | [81] |
| 2014-06-23 | CWE 2.7 | Standards | Software | Confirmed | [115] |
| 2014-06-25 to 2014-06-27 | ICS-CERT alert on Havex (ICS-ALERT-14-176-02, Update A on 27 Jun); Riley v. California decided | ICS; Courts | Energy; Cross-sector | Confirmed | [50][51][100] |
| 2014-06 to 2014-10 | CVE-2014-4114 exploited in the wild in a "Sandworm" attack, per NVD | Espionage | Government | Confirmed | [21] |
| 2014-06-30 | Microsoft's civil action against njRAT operators and No-IP's owner; Symantec's Dragonfly report (v1.21, 7 Jul) | Takedown; Espionage | Consumer; Energy | Confirmed | [92][52] |
| 2014-07-09 | Microsoft settles with Vitalwerks | Takedown | Internet | Confirmed | [92] |
| 2014-07-11 | Status report to W.D. Pa.: GameOver Zeus measures succeeded | Courts | Finance | Confirmed | [88] |
| 2014-07-15 | Google announces Project Zero | Vulnerability research | Software | Confirmed | [112] |
| 2014-07-23 | CAPEC 2.6; first MtGox creditor meeting | Standards; Courts | Software; Crypto exchange | Confirmed | [116][8] |
| 2014-07-31 | US-CERT TA14-212A, Backoff; CWE 2.8 | Crimeware; Standards | Retail; Software | Confirmed | [85][115] |
| 2014-08-07 | Kaspersky's Epic Turla report; Google starts using HTTPS as a ranking signal | Espionage; Internet | Government; Web | Confirmed | [57][110] |
| 2014-08-14 | SUPERVALU announces the intrusion | Breach | Retail | Confirmed | [81] |
| 2014-08-18 | Community Health Systems 8-K: about 4.5 million patients | Breach | Healthcare | Confirmed; Reported (attribution) | [49] |
| 2014-08-20 | Kaspersky publishes El Machete | Espionage | Government; military; diplomatic | Confirmed (vendor's finding) | [60] |
| 2014 (summer) | BlackEnergy samples tailored to Ukrainian government organizations, per F-Secure. Home: [Sandworm Operations](/case-studies/SANDWORM_OPERATIONS.md) | Espionage | Government | Confirmed (vendor's finding) | [55] |
| 2014-09 (early) | Kmart's store payment systems breached | Breach | Retail | Confirmed | [80] |
| 2014-09-02 | Apple on the celebrity account compromises; Home Depot begins its investigation | Breach | Consumer; Retail | Confirmed | [75][77] |
| 2014-09-05 | NATO Wales Summit endorses an Enhanced Cyber Defence Policy | Policy | Defense | Confirmed | [107] |
| 2014-09-08 | Home Depot confirms a payment-data breach | Breach | Retail | Confirmed | [77] |
| 2014-09-18 | Home Depot: about 56 million cards | Breach | Retail | Confirmed | [78] |
| 2014-09-24 to 2014-09-25 | NVD publishes Shellshock, CVE-2014-6271; US-CERT TA14-268A (revised 26 and 30 Sep) | Vulnerability | Cross-sector | Confirmed | [28][29] |
| 2014-09-30 | End of ICS-CERT's FY2014: 245 incidents | ICS | Energy; Cross-sector | Confirmed | [95] |
| 2014-10-02 | JPMorgan Chase 8-K | Breach | Finance | Confirmed | [76] |
| 2014-10-08 | ICS-CERT alert on BlackEnergy against internet-connected HMIs | ICS | Energy | Confirmed | [54] |
| 2014-10-09 to 2014-10-10 | Kmart detects the breach; Sears Holdings 8-K | Breach | Retail | Confirmed | [80] |
| 2014-10-14 | MS14-060 (CVE-2014-4114); Google discloses POODLE; Mozilla plans SSL 3.0 removal; Cisco Talos on Group 72 | Vulnerability; Espionage | Cross-sector; Internet | Confirmed | [20][31][32][46] |
| 2014-10-15 | OpenSSL adds TLS_FALLBACK_SCSV; NVD publishes CVE-2014-3566, CVE-2014-4114 and CVE-2014-4148; Drupal's patch deadline (23:00 UTC) | Vulnerability | Internet; Web | Confirmed | [33][35][21][22][39] |
| 2014-10-16 | NVD publishes Drupal CVE-2014-3704 | Vulnerability | Web | Confirmed | [38] |
| 2014-10-17 | US-CERT TA14-290A on POODLE; Executive Order 13681 | Vulnerability; Policy | Internet; Payments | Confirmed | [34][103] |
| 2014-10-22 | US-CERT TA14-295A, Crypto Ransomware | Crimeware | Cross-sector | Confirmed | [91] |
| 2014-10-29 | Drupal PSA-2014-003: assume compromise | Vulnerability | Web | Confirmed | [39] |
| 2014-11 | BSI's 2014 situation report, with the steel mill case | ICS | Manufacturing | Confirmed | [94] |
| 2014-11-06 | Home Depot 8-K on the vendor credentials and 53 million email addresses; Silk Road 2.0 operator arrested | Breach; Courts | Retail; Online markets | Confirmed (as charged, for Silk Road 2.0) | [79][93] |
| 2014-11-10 | Kaspersky publishes Darkhotel | Espionage | Executives; hospitality | Confirmed (vendor's finding) | [61][62] |
| 2014-11-11 | MS14-066 (Schannel, CVE-2014-6321) | Vulnerability | Cross-sector | Confirmed | [23][24] |
| 2014-11-13 | US-CERT TA14-317A, Masque Attack on iOS | Vulnerability | Mobile | Confirmed | [40] |
| 2014-11-18 | MS14-068 (Kerberos, CVE-2014-6324); MS14-066 re-offered; Let's Encrypt announced | Vulnerability; Internet | Cross-sector; Web | Confirmed | [25][23][111] |
| 2014-11-24 | Symantec and Kaspersky publish Regin (US-CERT TA14-329A, 25 Nov) | Espionage | Telecom; government | Confirmed | [63][64] |
| 2014-11 (late) | Sony Pictures Entertainment hit by destructive malware and data theft. Home: [North Korea-attributed threat actors](/case-studies/THREAT_ACTORS_NORTH_KOREA.md) | Destructive | Media and entertainment | Confirmed | [70] |
| 2014-11-25 | Firefox 34 ships with SSL 3.0 disabled by default | Vulnerability | Internet | Confirmed | [32] |
| 2014-11-26 | Second MtGox creditor meeting | Courts | Crypto exchange | Confirmed | [8] |
| 2014-12 | Cylance's Operation Cleaver report, as ATT&CK describes it | Espionage | Not stated in the source opened | Reported | [68] |
| 2014-12-08 to 2014-12-10 | Some TLS implementations found vulnerable to POODLE (CVE-2014-8730); MS14-066 re-offered (9 Dec); BlackEnergy alert updated (10 Dec) | Vulnerability; ICS | Internet; Energy | Confirmed | [34][23][54] |
| 2014-12-18 | FISMA 2014, the Cybersecurity Enhancement Act and the National Cybersecurity Protection Act enacted | Policy | Government; Critical infrastructure | Confirmed | [104][105][106] |
| 2014-12-19 | FBI attributes the Sony attack to North Korea; US-CERT TA14-353A; Staples announces POS malware at 115 stores | Destructive; Breach | Media; Retail | Confirmed | [70][71][84] |
| 2014-12-20 | US-CERT on Misfortune Cookie (VU#561444) | Vulnerability | Consumer; small office | Confirmed | [41] |
| 2014 (late) | Theft of data on at least 500 million Yahoo accounts (disclosed 2016; home: [2016 chronicle](/case-studies/CHRONICLE_2016.md)) | Breach | Internet | Confirmed; Reported (state sponsor) | [86] |
| 2014 (undated) | German steel mill attack; Dridex first appears; LibreSSL forked; Kimsuky and KHNP, per ATT&CK; APT28 operations of 2014 to 2018, per ATT&CK | ICS; Crimeware; Software; Espionage | Manufacturing; Finance; Nuclear; Sport and chemical-weapons bodies | Confirmed; Reported (ATT&CK's KHNP and APT28 lines) | [94][121][113][69][58] |
| 2015 to 2025 (boundary) | First new-syntax CVE ids (13 Jan 2015); Staples 10-K (6 Mar 2015); RFC 7507 (Apr 2015) and RFC 7568 (Jun 2015); ATT&CK public (May 2015); Yahoo 8-K (22 Sep 2016); ICS-CERT's Russian attribution of Havex and BlackEnergy (20 Jul 2021); KEV additions (Nov 2021 to Oct 2025) | Standards; Breach; ICS | Cross-sector | Confirmed | [114][84][36][117][86][51][54][27] |

## Part 2: the shared-code vulnerabilities

### Heartbleed

OpenSSL's advisory of 7 April described CVE-2014-0160 as a missing bounds check in the TLS heartbeat extension that could reveal up to 64k of memory, affecting OpenSSL 1.0.1 through 1.0.1f and 1.0.2-beta1, fixed in 1.0.1g (and 1.0.2-beta2), and credited Neel Mehta of Google Security (Confirmed [11]). CERT/CC's note said a remote, unauthenticated attacker could read up to 64 KB of process memory per request, exposing private keys and credentials, and told affected sites to regenerate keys and revoke the old ones (Confirmed [14]). US-CERT's TA14-098A added that the read could be repeated in 64k chunks, that keys from vulnerable versions should be regenerated after patching, and that Perfect Forward Secrecy limits the damage of a stolen key (Confirmed [12]). NVD published the record on 7 April with CWE-125, Out-of-bounds Read; CISA added it to KEV on 4 May 2022 (Confirmed [13]). Codenomicon's site says its engineers found the bug independently and asks that the duplicate id CVE-2014-0346 not be used (Reported [15]).

The CWE binds through NVD; the library's CAPEC data relates CAPEC-540, Overread Buffers, to CWE-125, which is this study's binding for the attack pattern (Inferred [122]). How often Heartbleed was exploited in 2014 was not checked.

### CCS injection

On 5 June OpenSSL disclosed CVE-2014-0224: a crafted handshake could force weak keying material, so a man-in-the-middle could decrypt and modify traffic between a vulnerable client and a vulnerable server (Confirmed [37]).

### Shellshock

NVD published CVE-2014-6271 on 24 September, a flaw in GNU Bash through 4.3 triggered by crafted environment variables, with CWE-78, OS Command Injection (Confirmed [28]). US-CERT's TA14-268A, first released on 25 September and revised on 26 and 30 September, listed CVE-2014-6271, CVE-2014-7169, CVE-2014-7186, CVE-2014-7187, CVE-2014-6277 and CVE-2014-6278 in Bash 1.14 through 4.3, named network paths through Apache mod_cgi and mod_cgid, OpenSSH's ForceCommand restriction and DHCP clients, and said the first fixes were incomplete (Confirmed [29]). KEV added CVE-2014-6271 and CVE-2014-7169 on 28 January 2022 and CVE-2014-6278 on 2 October 2025 (Confirmed [29][27]). ATT&CK's page for T1190, Exploit Public-Facing Application, cites CVE-2014-7169 as an example of an exploited internet-facing system (Confirmed [30]). The library relates CAPEC-88, OS Command Injection, to CWE-78; T1059.004, Unix Shell, is this study's binding for the execution step (Inferred [122]).

### POODLE and the end of SSL 3.0

On 14 October Google's security blog, by Bodo Moeller with Thai Duong and Krzysztof Kotowicz, disclosed POODLE, a design flaw in SSL 3.0. It recommended TLS_FALLBACK_SCSV, which Chrome and Google's servers had supported since February, and said Chrome was testing removal of the SSL 3.0 fallback (Confirmed [31]). Mozilla said SSL 3.0 would be off by default in Firefox 34, released on 25 November (Confirmed [32]). OpenSSL added TLS_FALLBACK_SCSV, developed by Adam Langley and Bodo Moeller, on 15 October and advised upgrading to 1.0.1j, 1.0.0o or 0.9.8zc (Confirmed [33]). US-CERT's TA14-290A of 17 October said SSL 3.0 itself could not be fixed and should be disabled, that the attack needs a man-in-the-middle position and so is somewhat difficult, and, in a December revision, that some TLS implementations were found vulnerable on 8 December (CVE-2014-8730) (Confirmed [34]). NVD lists CVE-2014-3566 with CWE-310 and the CNA lists CWE-329; it is not in KEV (Confirmed [35]). The responses were standardized in 2015 as RFC 7507, TLS Fallback SCSV (April), and RFC 7568, SSLv3 Is Not Secure (June) (Confirmed [36]).

ATT&CK's T1557, Adversary-in-the-Middle, describes downgrades to a weaker SSL or TLS version, and the library relates CAPEC-620, Drop Encryption Level, to CWE-757 and T1600, Weaken Encryption; both are this study's bindings for POODLE (Inferred [119][122]).

### goto fail

NVD published CVE-2014-1266 on 22 February: a signature-verification flaw in Apple's Secure Transport (SSLVerifySignedServerKeyExchange), with CWE-295, Improper Certificate Validation (Confirmed [6]). Apple's own bulletin was not opened.

### The institutional response

Google announced Project Zero on 15 July as a full-time team hunting vulnerabilities in widely used software, citing Heartbleed as a product of earlier part-time research (Confirmed [112]). LibreSSL says it was forked from OpenSSL in 2014 inside OpenBSD to modernize the codebase and improve security (Confirmed [113]). In May the IETF published RFC 7258 (BCP 188), which treats pervasive monitoring as a technical attack to be mitigated in protocol design (Confirmed [109]). On 7 August Google began using HTTPS as a lightweight ranking signal, affecting fewer than 1 percent of global queries at launch (Confirmed [110]). On 18 November the EFF announced Let's Encrypt with Mozilla, Cisco, Akamai, IdenTrust and University of Michigan researchers, a free and automated certificate authority scheduled for summer 2015 (Confirmed [111]). The Linux Foundation's Core Infrastructure Initiative announcement was not checked.

## Part 3: the Microsoft, browser and web record

### Internet Explorer zero-days

US-CERT reported on 14 February that the IE 9 and 10 use-after-free CVE-2014-0322 was being actively exploited; NVD lists CWE-416, and KEV added it on 4 May 2022 (Confirmed [5]). On 26 April Microsoft published Security Advisory 2963983 for CVE-2014-1776, a memory-corruption flaw affecting IE 6 through 11, crediting FireEye; NVD published the record on 27 April with CWE-416, and KEV added it on 28 January 2022 (Confirmed [127][27]). US-CERT reported active exploitation on 28 April (Confirmed [16]). Microsoft fixed it out of band in MS14-021 on 1 May, said it was aware of limited, targeted attacks, and included updates for IE 6, 7 and 8 on Windows XP SP3 even though XP support had ended (Confirmed [18]). ATT&CK records that APT3 (G0022) exploited CVE-2014-1776 in Operation Clandestine Fox, citing FireEye's post of 26 April, and that researchers attribute APT3 to China's Ministry of State Security, a later record; the FireEye post itself was not opened (Reported [48]).

### Windows XP's end

US-CERT's TA14-069A warned in March that Microsoft would end support for Windows XP and Office 2003 on 8 April (Confirmed [9]). Microsoft's lifecycle table lists the extended end date for XP and SP3 as 4/9/2014 6:59:59 AM, which, read as UTC, is the last second of 8 April Pacific time (Confirmed [10]; Inferred for the time-zone reading). Three weeks later MS14-021 shipped an XP fix anyway (Confirmed [18]).

### Microsoft's other bulletins under attack

- **MS14-025 (13 May).** It fixed CVE-2014-1812, an elevation of privilege through passwords stored in Group Policy Preferences. The flaw was publicly disclosed, Microsoft was aware of targeted attacks, and the update stopped new GPP passwords but did not remove those already in Group Policy objects (Confirmed [19]). KEV flags CVE-2014-1812 for known ransomware use, the only 2014 CVE so flagged (Confirmed [19][27]).
- **MS14-060 (14 October).** It fixed the Windows OLE remote code execution flaw CVE-2014-4114, rated Important; Microsoft knew of limited, targeted attacks using PowerPoint files and credited iSIGHT Partners and ESET (Confirmed [20]). NVD records that it was exploited in the wild in a "Sandworm" attack from June through October 2014 and lists no CWE (NVD-CWE-noinfo); KEV added it on 3 March 2022 (Confirmed [21]). CISA added the follow-on CVE-2014-6352 to KEV on 25 February 2022 (Confirmed [27]). NVD also published the win32k.sys flaw CVE-2014-4148 (CWE-94) on 15 October, and KEV added it on 25 May 2022 (Confirmed [22]). The home for the Sandworm thread is [Sandworm Operations](/case-studies/SANDWORM_OPERATIONS.md).
- **MS14-066 (11 November).** It fixed the Schannel remote code execution flaw CVE-2014-6321, rated Critical on every supported Windows version, with no known exploitation at release; Microsoft re-offered it on 18 November and 9 December over TLS cipher-suite issues (Confirmed [23]). NVD lists CWE-94, and it is not in KEV (Confirmed [24]).
- **MS14-068 (18 November).** It fixed CVE-2014-6324 in the Kerberos Key Distribution Center, rated Critical on server editions: an authenticated domain user could get a forged ticket accepted as a domain administrator's. Microsoft knew of limited, targeted attacks and said they did not affect Windows Server 2012 and 2012 R2 (Confirmed [25]). KEV added it on 25 March 2022 (Confirmed [26]). ATT&CK's T1212, Exploitation for Credential Access, gives MS14-068 as its example, and its T1068 entry lists Threat Group-3390 (G0027) as having used CVE-2014-6324 (Confirmed [118]; Demonstrated [121]).

MS14-021 (1 May) and MS14-068 (18 November) both shipped outside the second-Tuesday cycle; the Patch Tuesdays in those months were 13 May and 11 November (Inferred [18][25]).

### Drupal

NVD published CVE-2014-3704 on 16 October: SQL injection in the database abstraction API of Drupal core 7.x before 7.32, CWE-89; it is not in KEV (Confirmed [38]). Drupal's PSA-2014-003 of 29 October said automated attacks began within hours of the core advisory, that owners should assume every Drupal 7 site was compromised unless it was patched before 15 October 23:00 UTC, and that patching does not remove backdoors, so sites should restore from backups made before 15 October (Confirmed [39]). The core advisory page itself would not open. The library relates CAPEC-66, SQL Injection, to CWE-89 (Demonstrated [122]).

### Other disclosures

- **Masque Attack.** US-CERT's TA14-317A of 13 November warned that on iOS 7.1.1 through 8.1.1 beta an app installed from outside the App Store could replace a legitimate app (Confirmed [40]). ATT&CK for Mobile is not bound in this study.
- **Misfortune Cookie.** US-CERT warned on 20 December that broadband routers running Allegro RomPager before 4.34 had a cookie-processing flaw allowing remote takeover (VU#561444) (Confirmed [41]).
- **NTP monlist.** NVD published CVE-2013-5211 on 2 January with CWE-20, and US-CERT's alert of 13 January described its use to amplify DDoS (Confirmed [4]).

### The KEV tail

KEV catalog 2026.11.10 holds 1,779 entries, 34 of them CVE-2014 ids, every one added on 3 November 2021 or later; examples are CVE-2014-0160, CVE-2014-6271, CVE-2014-1776, CVE-2014-4114, CVE-2014-6324, CVE-2014-6352, CVE-2014-3153, CVE-2014-4113, CVE-2014-6287, CVE-2014-3120 and CVE-2014-8361 (Confirmed [27]). KEV records known exploitation; it does not date it (Inferred [27]).

## Part 4: China-attributed espionage and the first indictment

### The Unit 61398 indictment

On 1 May a Western District of Pennsylvania grand jury indicted five officers of the PLA's 3PLA Second Bureau, Third Office, Military Unit Cover Designator 61398, on 31 counts: conspiring to commit computer fraud, unauthorized access for commercial advantage, damaging computers, aggravated identity theft, economic espionage and theft of trade secrets (Confirmed as charged [43]). The FBI announced the case on 19 May and named the defendants (Wang Dong, Sun Kailiang, Wen Xinyu, Huang Zhenyu and Gu Chunhui) and the victims (Westinghouse, SolarWorld's US subsidiaries, US Steel, Allegheny Technologies, the United Steelworkers union and Alcoa) for conduct from 2006 to 2014, calling it the first time criminal charges were filed against known state actors for hacking (Confirmed [42][43]). ATT&CK's G0006, APT1, is attributed to the same unit (Confirmed [121]). The home for APT1 and the indictment is [China-attributed threat actors](/case-studies/THREAT_ACTORS_CHINA.md), and [The Hacker and the State](/case-studies/HACKER_AND_THE_STATE_CASES.md) covers the indictment as a turning point in state attribution (Confirmed [126]).

### Putter Panda

CrowdStrike's 9 June report attributed espionage against US defense and European satellite and aerospace firms to PLA 3rd GSD 12th Bureau, Unit 61486, in Shanghai, with activity dating to 2007 and malware delivered through Adobe Reader and Office exploits in targeted email (Confirmed as CrowdStrike's finding [44]). The full report says the operators' domains were registered to an address matching the 12th Bureau's Shanghai headquarters and that CrowdStrike had tracked the unit since 2012 (Confirmed [45]). ATT&CK records the group as G0024 (Demonstrated [121]).

### Axiom and Group 72

Cisco Talos described Group 72 on 14 October as "involved in Operation SMN, named Axiom by Novetta", sophisticated, well funded and after high-value intellectual property (Confirmed [46]). ATT&CK's G0001, Axiom, calls it a suspected Chinese espionage group active since at least 2008, cites Novetta's Operation SMN report, and binds T1189 and T1566 to the Talos post (Confirmed [47][46]). The Novetta report was not opened.

### Community Health Systems

The hospital operator's 8-K of 18 August said an external criminal attack in April and June 2014 copied non-medical patient identification data (names, addresses, birthdates, phone numbers and Social Security numbers) on about 4.5 million people, and US-CERT issued an alert the same day (Confirmed [49]). The company and its responder, Mandiant, believed the attacker was an Advanced Persistent Threat group originating from China; that is the company's belief, not a government or court finding, and no ATT&CK group is bound (Reported [49]).

## Part 5: the wider state and espionage record

### Russia-linked reporting

- **Dragonfly and Havex.** ICS-CERT's alert, first published 25 June and updated on 27 June, and its advisory ICSA-14-178-01 described a campaign that infected victims through phishing, redirects from compromised websites and trojanized installers on at least three ICS vendor sites, with a payload that enumerated OPC Classic servers and tags and caused some OPC platforms to crash (Confirmed [50][51]). Symantec's report of 30 June (v1.21, 7 July) described Dragonfly, also called Energetic Bear, as active since at least 2011, moving in early 2013 from US and Canadian defense and aviation targets to US and European energy firms, using Backdoor.Oldrea, Trojan.Karagany, the Lightsout exploit kit and compromised ICS software update sites, with compile times that fit a 9-to-6 workday in UTC+4 (Confirmed as Symantec's finding [52]). Symantec named no state. ICS-CERT's update of 20 July 2021 attributes the activity to Russian nation-state actors, and ATT&CK now attributes G0035 to FSB Center 16, both later records (Confirmed [51]; Demonstrated [121]). The home for Dragonfly as a group is [Russia-attributed threat actors](/case-studies/THREAT_ACTORS_RUSSIA.md); this chronicle is the library's record of the 2014 Havex campaign.
- **BlackEnergy and Quedagh.** F-Secure reported that in summer 2014 BlackEnergy samples were tailored to target Ukrainian government organizations, named the operators Quedagh, and identified a BlackEnergy 3 variant with User Account Control and driver-signing bypasses; it named no state (Confirmed as F-Secure's finding [55]). ATT&CK's S0089 maps T1548.002 and T1553.006 and describes BlackEnergy as used by criminal and APT actors since at least 2007; the library carries Quedagh as an alias of G0034, Sandworm Team (Confirmed [55][56]; Demonstrated [121]). The ICS side of BlackEnergy is in Part 9, and the home is [Sandworm Operations](/case-studies/SANDWORM_OPERATIONS.md).
- **Epic Turla.** Kaspersky reported on 7 August that several hundred computers in more than 45 countries had been infected, in government, embassies, military, education, research and pharmaceutical organizations, through the zero-days CVE-2013-5065 and CVE-2013-3346 and watering holes. The Epic (Tavdig) backdoor was the first stage before Carbon (Cobra) and the Snake (Uroburos) rootkit, and the campaign was still active in July 2014 (Confirmed as Kaspersky's finding [57]). ATT&CK records G0010 Turla, S0091 Epic and S0022 Uroburos, which maps T1014; the FSB attribution in ATT&CK is a later record (Confirmed [57]; Demonstrated [121]).
- **APT28.** ATT&CK's G0007 records that a 2018 US indictment charged five GRU Unit 26165 officers associated with APT28 for operations from 2014 to 2018 against WADA, USADA, a US nuclear facility, the OPCW and the Spiez laboratory; the indictment itself was not opened (Reported [58]).

### Regin

Kaspersky reported on 24 November that the Regin platform had samples timestamped back to 2003 and 27 victims in 14 countries: telecom operators (with GSM targeting), government, multinational political bodies, financial and research institutions, and a cryptographer who disclosed his intrusion in February 2014. Lateral movement used Windows admin shares. Kaspersky said Regin was likely supported by a nation-state and named no country (Confirmed as Kaspersky's finding [63]). US-CERT's TA14-329A noted Symantec's report of the same day and said Regin had not been seen targeting US organizations (Confirmed [64]). ATT&CK's S0019 cites Kaspersky's report and maps T1040, T1021.002, T1564.004 and T1564.005, among others (Confirmed [65]). Press attributions to Five Eyes agencies were not checked. The home is [The Hacker and the State](/case-studies/HACKER_AND_THE_STATE_CASES.md).

### Careto

Kaspersky reported on 10 February that Careto, or The Mask, had run since at least 2007 and reached more than 1,000 IP addresses in 31 countries, in government, diplomatic, energy, research, private-equity and activist targets. Kaspersky said it could be a state-sponsored operation, declined to attribute it and called the Spanish-language clue weak (Confirmed [59]). The library's ATT&CK data has no Careto object, so it stays unbound (Demonstrated [121]).

### El Machete

Kaspersky reported on 20 August a Spanish-speaking espionage campaign that began in 2010 and was renewed in 2012. Its malware captured keystrokes, audio, screenshots, geolocation, webcam photos and clipboard data and copied files to USB drives, against intelligence services, military, embassies and government mainly in Venezuela, Ecuador, Colombia, Peru, Russia, Cuba and Spain (Confirmed [60]). ATT&CK records G0095 Machete and the software S0409, which maps T1056.001, T1123, T1113, T1125, T1115 and T1052.001 (Confirmed [60]; Demonstrated [121]). The home is [Other states' threat actors](/case-studies/THREAT_ACTORS_OTHER_STATES.md).

### Darkhotel

Kaspersky reported on 10 November an actor that used hotel networks to reach selected travelling executives, mostly from August 2010 to 2013 with some 2014 events still under investigation. It used Flash zero-days and abused at least ten certificate authorities to sign its code, and about 90 percent of infections were in Japan, Taiwan, China, Russia and South Korea (Confirmed as Kaspersky's finding [61]). The report's PDF notes a self-kill routine when the system's default codepage is Korean and keylogger strings mixing English and Korean (Confirmed [62]). Kaspersky named no state; ATT&CK's G0012 now says suspected South Korean and binds T1189, T1553.002 and T1056.001 to the 2014 report (Confirmed [61]). The home is [Other states' threat actors](/case-studies/THREAT_ACTORS_OTHER_STATES.md).

### Iran-linked reporting (summary)

CrowdStrike reported on 13 May an Iran-based actor it called FLYING KITTEN, tracked since mid-January, which FireEye released the same day as Saffron Rose; it targeted US defense contractors and political dissidents with spoofed login pages that then delivered Stealer malware (Confirmed as CrowdStrike's assessment [66]). ATT&CK records it as G0130, Ajax Security Team, and binds T1566.003 to Saffron Rose (Confirmed [121]). eWeek, reporting iSIGHT's findings, said the Newscaster campaign used fake social-media personas to target organizations in the US, UK and Israel and reached at least 2,000 people, and that iSIGHT attributed it to Iran; ATT&CK's G0059, Magic Hound, lists Newscaster as an alias (Reported [67]; Demonstrated [121]). ATT&CK's G0003 says Cleaver, responsible for Cylance's Operation Cleaver of December 2014, has been attributed to Iranian actors (Reported [68]). The February attack on Las Vegas Sands is graded Reported in its home, [Iran-attributed threat actors](/case-studies/THREAT_ACTORS_IRAN.md) (Reported [126]).

### Disclosure years, not start years

For this part of the record 2014 was mostly the year operations were disclosed, not the year they started: Regin samples date to 2003, Careto to 2007, Darkhotel's hotel activity to 2010 and Putter Panda to 2007. Most 2014 vendor reports named no state, and today's ATT&CK attributions (FSB Center 16 for Dragonfly, the MSS for APT3, South Korea for Darkhotel, Russia for the BlackEnergy HMI campaign as of 2021) are later records (Inferred [63][59][61][44][52][55]).

## Part 6: Sony Pictures and North Korea

The FBI's update of 19 December said Sony Pictures Entertainment confirmed in late November that it had been hit by an attack that deployed destructive malware, stole proprietary data and employee personal information, and rendered thousands of computers inoperable, and that a group calling itself the Guardians of Peace claimed it. The FBI said it had enough information to conclude that the North Korean government was responsible, citing similarities in code, encryption and data-deletion methods, overlap with infrastructure tied to North Korea, and similarity to the March 2013 attacks on South Korean banks and media, and noted that Sony reported the incident within hours (Confirmed [70]).

US-CERT's TA14-353A, issued the same day, named only "a major entertainment company" and no actor. It described an SMB worm that spread by guessing passwords for Windows shares, a listening implant, a lightweight backdoor, a proxy tool, a destructive hard-drive tool that overwrites up to four drives and the master boot record, and a destructive target-cleaning tool, and recommended antivirus, patching and US-CERT's tip ST13-003 on handling destructive malware (Confirmed [71]).

ATT&CK lists Guardians of Peace as an alias of G0032, Lazarus Group, and describes the group as reportedly responsible for the November 2014 wiper attack, citing Novetta's 2016 Operation Blockbuster report (Confirmed [72]). The Lazarus entries that match TA14-353A's tools (T1110.003, T1021.002, T1561.001, T1561.002, T1485, T1543.003 and T1571, plus T1491.001) cite Novetta 2016 and US-CERT 2018 rather than 2014 records, so their binding to 2014 is retrospective (Confirmed [72]; Inferred for the binding). ATT&CK's G0094 says Kimsuky was assessed to be responsible for the 2014 Korea Hydro and Nuclear Power compromise (Reported [69]). The home is [North Korea-attributed threat actors](/case-studies/THREAT_ACTORS_NORTH_KOREA.md), and [The Hacker and the State](/case-studies/HACKER_AND_THE_STATE_CASES.md) covers the case too (Confirmed [126]).

## Part 7: breaches and data loss

### The point-of-sale year

- **Target (summary).** The FY2013 10-K, filed 14 March, says an intruder stole data from about 40 million credit and debit card accounts used in US stores between 27 November and 15 December 2013 through malware on the point-of-sale system, and names, mailing addresses, phone numbers or email addresses for up to 70 million people. Target first believed only card data was taken, then found other guest information was too, and recorded USD 61 million of pretax breach expenses against USD 44 million of expected insurance, a net of USD 17 million (Confirmed [1]). The Senate Commerce majority staff report of 26 March says up to 110 million customers were affected and that the attackers' foothold came through access Target had given a small Pennsylvania HVAC vendor, with automated warnings not acted on, and states that it is based on media reports and expert analyses (Confirmed for the report [2]; Reported for the vendor detail [2]). The home is [E-Commerce Threats](/case-studies/ECOMMERCE_THREATS.md), section 2.5 (Confirmed [126]).
- **Neiman Marcus.** Its 10-Q of 12 March says malware found in January 2014 had tried to collect card data from 16 July to 30 October 2013 at 77 of 85 stores, and about 350,000 cards could have been collected (Confirmed [82]).
- **Michaels and Aaron Brothers.** The 10-K of 29 April says previously unseen malware hit Michaels stores from 8 May 2013 to 27 January 2014 (about 2.6 million cards) and 54 Aaron Brothers stores from 26 June 2013 to 27 February 2014 (about 400,000 cards) (Confirmed [83]).
- **Backoff.** US-CERT's TA14-212A of 31 July said variants dated from October 2013, that attackers brute-forced remote-desktop logins and then deployed memory-scraping point-of-sale malware with keylogging and HTTP POST command and control, and that the Secret Service estimated more than 1,000 US businesses were affected; seven POS vendors confirmed multiple affected clients (Confirmed [85]). TA14-002A had warned retailers about POS malware on 2 January (Confirmed [3]).
- **SUPERVALU.** It announced on 14 August a criminal intrusion into its card-processing network that may have exposed cards used from 22 June to 17 July at 180 stores and 29 franchised Cub Foods stores, without having determined that data was stolen (Confirmed [81]).
- **Home Depot.** Its 8-K of 8 September confirmed a breach of payment data systems affecting US and Canadian stores from April 2014, after an investigation that began on 2 September on reports from banks and law enforcement (Confirmed [77]). The 18 September 8-K said custom-built malware present from April to September put about 56 million unique payment cards at risk, put gross costs at about USD 62 million against a USD 27 million insurance receivable, and found no evidence that debit PINs were compromised (Confirmed [78]). The 6 November 8-K said criminals used a third-party vendor's user name and password to enter the network perimeter, acquired elevated rights, deployed custom-built malware on self-checkout systems, and took separate files with about 53 million email addresses (Confirmed [79]). The home is [E-Commerce Threats](/case-studies/ECOMMERCE_THREATS.md), section 2.6 (Confirmed [126]).
- **Kmart.** The Sears Holdings 8-K of 10 October said Kmart detected on 9 October that its store payment systems had been breached since early September by malware that current antivirus could not detect; card numbers were believed compromised, but not PINs, email addresses or Social Security numbers, and kmart.com was not shown to be affected (Confirmed [80]).
- **Staples.** Its 10-K, filed 6 March 2015, records that on 19 December 2014 it announced point-of-sale malware at 115 of its more than 1,400 US stores, which may have exposed names, card numbers, expiration dates and verification codes for about 1.16 million cards (Confirmed [84]).

### Other breaches

- **eBay.** On 21 May eBay asked users to change passwords: a small number of employee log-in credentials had been used to reach the corporate network and a database of names, encrypted passwords, email and physical addresses, phone numbers and dates of birth, compromised between late February and early March. It found no evidence of access to financial data (Confirmed [73][74]).
- **Celebrity Apple accounts.** Apple said on 2 September that certain celebrity accounts were compromised by a very targeted attack on user names, passwords and security questions, and that none of the cases came from a breach of any Apple system, including iCloud or Find my iPhone; it advised strong passwords and two-step verification (Confirmed [75]).
- **JPMorgan Chase.** Its 8-K of 2 October said user contact information (name, address, phone number and email address) and internal information were compromised for about 76 million households and 7 million small businesses, with no evidence that account numbers, passwords, user IDs, dates of birth or Social Security numbers were compromised and no unusual fraud (Confirmed [76]).
- **Community Health Systems (summary).** About 4.5 million patients' identity data; see Part 4 (Confirmed [49]).
- **Yahoo (summary).** Yahoo said in a September 2016 filing that information from at least 500 million accounts was stolen in late 2014, including names, email addresses, phone numbers, dates of birth, hashed passwords and some security questions, and that it believed the thief was a state-sponsored actor, which is the company's belief (Confirmed [86]; Reported for the state sponsor). The home is the [2016 chronicle](/case-studies/CHRONICLE_2016.md) (Confirmed [126]).
- **MtGox.** On 28 February MtGox Co., Ltd. applied for civil rehabilitation at the Tokyo District Court, which accepted the application that day. The company said its liabilities exceeded its assets and that the increase "may be linked to a loss of bitcoins and customer funds", reported that about 750,000 user bitcoins and about 100,000 of its own had disappeared, probably stolen through abuse of a bug in the bitcoin system (its belief), and put cash discrepancies at about JPY 2.8 billion (Confirmed [7]). The trustee's site lists a US Chapter 15 application on 14 March, the start of bankruptcy proceedings on 24 April, US recognition on 18 June, and creditor meetings on 23 July and 26 November (Confirmed [8]).
- **OPM (summary).** The 2014 OPM intrusions, with a US-CERT notice on 20 March 2014 and exfiltration in July and August and in December 2014, are graded Confirmed in their home, [The Hacker and the State](/case-studies/HACKER_AND_THE_STATE_CASES.md) (Confirmed [126]).

The data lost differed by victim: card data at the retailers, contact data at JPMorgan, credentials and profiles at eBay, identity data at CHS (Inferred [76][73][49]).

## Part 8: crimeware, takedowns and the courts

### Blackshades

On 19 May the FBI and the Southern District of New York announced the unsealed indictment of Swedish national Alex Yucel and the guilty plea of US citizen Michael Hogue, alleged co-developers of the Blackshades remote-access tool, which had been sold to thousands of people in more than 100 countries and used to infect more than half a million computers. Forty FBI field offices and 18 other countries took part, more than 1,900 domains were seized, and there were more than 90 arrests and more than 300 searches; the case spun out of Operation Cardshop (Confirmed as charged [87]). The library's ATT&CK data has no BlackShades object (Demonstrated [121]).

### GameOver Zeus and CryptoLocker

On 2 June the Department of Justice and FBI announced a multinational disruption of the GameOver Zeus botnet and CryptoLocker. Charges were unsealed in Pittsburgh and Omaha against Evgeniy Mikhailovich Bogachev of Anapa, Russia, the alleged administrator; more than a million computers were infected, about 25 percent in the US, and losses were estimated at more than USD 100 million. Court orders in Pittsburgh redirected the peer-to-peer bots to government servers and CryptoLocker's command servers were seized, and an 11 July status report said the measures succeeded (Confirmed [88]). The FBI's wanted page says a W.D. Pa. grand jury indicted Bogachev in his true name on 19 May and a District of Nebraska complaint of 30 May tied the nickname "lucky12345" to him (Confirmed as charged [89]). US-CERT's TA14-150A described GameOver Zeus as a peer-to-peer Zeus variant first identified in September 2011 that spreads by spam and phishing, harvests banking credentials and is associated with CryptoLocker (Confirmed [90]). ATT&CK carries it as S0016, P2P ZeuS, alias Gameover ZeuS, mapped to T1001.001 (Confirmed [121]). Bogachev's December 2016 Treasury designation is in the [2016 chronicle](/case-studies/CHRONICLE_2016.md) (Confirmed [126]).

### Crypto ransomware

US-CERT's TA14-295A of 22 October, drawn from Canadian CCIRC analysis coordinated with DHS, said ransoms typically ran USD 100 to 300, were sometimes demanded in bitcoin, and spread through phishing attachments and drive-by downloads (Confirmed [91]). CryptoLocker has no ATT&CK object (Demonstrated [121]).

### No-IP and njRAT

On 30 June Microsoft filed a civil suit in Nevada federal court against operators of the Bladabindi and Jenxcus malware (njRAT) and against Vitalwerks, the owner of No-IP, citing 93 percent use of No-IP domains and 7.4 million detections in 12 months, and announced a settlement with Vitalwerks on 9 July (Confirmed [92]). ATT&CK records njRAT as S0385 (Demonstrated [121]).

### Silk Road 2.0

The FBI's New York office announced on 6 November the arrest in San Francisco of Blake Benthall, "Defcon", the alleged operator of Silk Road 2.0, which allegedly did about USD 8 million a month in sales and had about 150,000 active users (Confirmed as charged [93]). Europol's Operation Onymous release was not checked.

### Banking Trojans and financial crime that ATT&CK dates to 2014

ATT&CK records that Emotet (S0367) first emerged in June 2014, targeting the financial sector, and that Dridex (S0384) first appeared in 2014; it records Carbanak (G0008, using S0030) against financial institutions since at least 2013, and the library also has pages for Dyre (S0024) and Mimikatz (S0002), whose 2014 dates were not opened (Confirmed [121]).

### Denial of service

US-CERT's alert of 13 January described NTP amplification attacks using the monlist feature, CVE-2013-5211 (Confirmed [4]). Akamai's purchase of Prolexic and the Monsegur sentence are in [Cybercrime and Hacktivism in Four Books](/case-studies/CYBERCRIME_FOUR_BOOKS.md) (Confirmed [126]).

## Part 9: industrial systems

**Havex.** The ICS-CERT alert and advisory described three infection vectors (phishing, watering-hole redirects and trojanized installers on at least three ICS vendor sites) and an OPC payload that enumerated servers and tags and crashed some OPC platforms (Confirmed [50][51]). ATT&CK's S0093, Backdoor.Oldrea (Havex), lists eight ICS techniques citing Symantec (30 June and 7 July 2014) and F-Secure (23 June 2014), and the library's ICS data maps G0035 to T0817 and T0862 (Confirmed [53]; Demonstrated [121]). S0094 Trojan.Karagany is the other Dragonfly tool in the record (Demonstrated [121]).

**BlackEnergy on HMIs.** ICS-CERT's alert, first sent as TLP Amber on 8 October and updated on 10 December, described a BlackEnergy variant compromising internet-connected HMIs running GE Cimplicity, Advantech/Broadwin WebAccess and Siemens WinCC, a campaign running since at least 2011, with GE Cimplicity CVE-2014-0751 exploited since at least January 2012. Only the 20 July 2021 update adds that the US Government attributes the activity to Russian nation-state cyber actors (Confirmed [54]). [Sandworm Operations](/case-studies/SANDWORM_OPERATIONS.md) is the home and records the alert with an update of 17 October 2014 (Confirmed [126]).

**The German steel mill.** BSI's report on the state of IT security in Germany in 2014 (section 3.3.1) describes a targeted attack on a steel mill: spear-phishing and social engineering gave access to the office network, the attackers worked into the production networks, control components failed more and more often, and a blast furnace could not be shut down in a controlled way, causing massive damage. BSI rated the attackers' technical capabilities as very advanced and gave no victim name and no date (Confirmed [94]).

**The year in numbers.** ICS-CERT's Monitor counted 245 incidents in fiscal year 2014, with energy leading at 79 (32 percent), about 55 percent involving APT or sophisticated actors, and most with an unknown access vector (Confirmed [95]).

## Part 10: law, policy and standards

### United States

- **PPD-28 (17 January)** set limits on the use of signals intelligence collected in bulk (Confirmed [97]).
- **Cybersecurity Framework 1.0 (12 February).** NIST released the voluntary, risk-based framework called for by Executive Order 13636, with five Functions (Identify, Protect, Detect, Respond, Recover) and Implementation Tiers (Confirmed [96]).
- **SEC (15 April and 10 June).** OCIE announced cybersecurity examinations of more than 50 registered broker-dealers and investment advisers, noting the 26 March roundtable, and Commissioner Luis Aguilar spoke at the NYSE on boards of directors and cyber risk (Confirmed [101][102]).
- **Riley v. California (25 June).** The Supreme Court held that police must get a warrant before searching a cell phone seized incident to arrest; the opinion was read on Cornell's Legal Information Institute because the Court's PDF link returned an error (Confirmed [100]).
- **Executive Order 13681 (17 October)** required enhanced security features, including chip-and-PIN, on government payment cards, with new terminals acquired through the listed channels to support them by 1 January 2015 (Confirmed [103]).
- **Three laws on 18 December.** The Federal Information Security Modernization Act of 2014 (Public Law 113-283) replaced the information security subchapter of chapter 35 of title 44 and requires agencies to notify Congress of a major incident within seven days; the Cybersecurity Enhancement Act of 2014 (Public Law 113-274) directs NIST to support a voluntary, consensus-based, industry-led set of standards for critical infrastructure; and the National Cybersecurity Protection Act of 2014 (Public Law 113-282) codified the NCCIC as section 226 of the Homeland Security Act (Confirmed [104][105][106]).
- **Vulnerability disclosure.** Michael Daniel's statement of 28 April 2014 on the vulnerability-disclosure process is in its home, [NSA and CIA tool leaks](/case-studies/NSA_CIA_TOOL_LEAKS.md) (Confirmed [126]).

### Europe and NATO

- **Digital Rights Ireland (8 April).** The Court of Justice of the EU declared the Data Retention Directive invalid (Confirmed [98]).
- **Google Spain (13 May).** The court held that a search engine operator is responsible for its processing of personal data on third-party pages and that people may seek removal of name-based result links (Confirmed [99]).
- **Cyber Essentials.** GOV.UK first published the scheme overview on 7 April and the Summary, Requirements and Assurance Framework on 5 June (Confirmed [108]).
- **NATO Wales Summit (5 September).** The declaration endorsed an Enhanced Cyber Defence Policy, affirmed that international law applies in cyberspace and that cyber defence is part of collective defence, and left any Article 5 invocation to the North Atlantic Council case by case (Confirmed [107]).

### Standards and catalogs

The CVE syntax change took effect on 1 January, and the first ids in the new syntax were issued on 13 January 2015 (Confirmed [114]). CWE 2.6 (19 February), 2.7 (23 June) and 2.8 (31 July) and CAPEC 2.3 (6 February), 2.4 (10 April), 2.5 (7 May) and 2.6 (23 July) were released (Confirmed [115][116]). ATT&CK was not yet public (Confirmed [117]). RFC 7258 and the 2015 RFCs on SSL 3.0 are in Part 2.

## Part 11: the defender view

**Shared code needed an owner and an inventory.** Heartbleed, CCS injection and Shellshock sat in a library and a shell that many products shipped, and the first Shellshock fixes were incomplete (Confirmed [11][37][29]; Inferred for the product reach). [Software Inventory](/mitre/d3fend/software-inventory.md) and [Software Update](/mitre/d3fend/software-update.md) are the library's D3FEND pages for knowing and fixing what runs, and [M1016 Vulnerability Scanning](/mitre/mitigations/M1016.md) and [M1051 Update Software](/mitre/mitigations/M1051.md) are the ATT&CK mitigations (Demonstrated [123][124]; Inferred for the pairing).

**Patching was not enough after a memory leak or a backdoor.** US-CERT told Heartbleed victims to regenerate keys, and Drupal told owners to restore from pre-October backups (Confirmed [12][39]). The library links [Credential Rotation](/mitre/d3fend/credential-rotation.md), [Credential Revocation](/mitre/d3fend/credential-revocation.md) and [Reissue Credential](/mitre/d3fend/reissue-credential.md) to credential techniques such as T1558, and [Restore Software](/mitre/d3fend/restore-software.md) to T1195.002 (Demonstrated [123]); pairing them with key regeneration is this study's reading (Inferred).

**Broken protocols had to be removed.** SSL 3.0 could not be fixed; TLS_FALLBACK_SCSV and Firefox 34's default closed the downgrade (Confirmed [34][33][32]). [Message Encryption](/mitre/d3fend/message-encryption.md) and [Certificate Pinning](/mitre/d3fend/certificate-pinning.md) are the D3FEND pages that fit the protocol layer; the library maps Message Encryption only to this study's Havex ICS ids (T0861, T0846, T0888, T0802), not to any of its Enterprise ids (Confirmed [123]; Inferred for the pairing). [M1041 Encrypt Sensitive Information](/mitre/mitigations/M1041.md) and [M1042 Disable or Remove Feature or Program](/mitre/mitigations/M1042.md) are the ATT&CK mitigations (Inferred).

**Client exploits needed exploit protection while fixes were pending.** IE CVE-2014-0322 and CVE-2014-1776 and the OLE flaw were exploited before or at their fixes (Confirmed [5][16][20]). The library links [Process Segment Execution Prevention](/mitre/d3fend/process-segment-execution-prevention.md), [Segment Address Offset Randomization](/mitre/d3fend/segment-address-offset-randomization.md), [Stack Frame Canary Validation](/mitre/d3fend/stack-frame-canary-validation.md) and [Memory Boundary Tracking](/mitre/d3fend/memory-boundary-tracking.md) to T1203 and T1068 (Demonstrated [123]); [M1050 Exploit Protection](/mitre/mitigations/M1050.md) and [M1048 Application Isolation and Sandboxing](/mitre/mitigations/M1048.md) are the ATT&CK mitigations (Inferred).

**Remote and vendor access needed MFA and a boundary.** Backoff brute-forced remote desktop, Home Depot's attackers used a vendor's credentials, and Target's reportedly came through an HVAC vendor (Confirmed [85][79]; Reported [2]). The library links [Connection Attempt Analysis](/mitre/d3fend/connection-attempt-analysis.md), [Session Termination](/mitre/d3fend/session-termination.md) and [Remote Terminal Session Detection](/mitre/d3fend/remote-terminal-session-detection.md) to T1199, [Account Locking](/mitre/d3fend/account-locking.md), [User Account Permissions](/mitre/d3fend/user-account-permissions.md) and [Access Modeling](/mitre/d3fend/access-modeling.md) to T1078, and [Strong Password Policy](/mitre/d3fend/strong-password-policy.md), [Multi-factor Authentication](/mitre/d3fend/multi-factor-authentication.md) and [Change Default Password](/mitre/d3fend/change-default-password.md) to T1110.003 (Demonstrated [123]); [M1032 Multi-factor Authentication](/mitre/mitigations/M1032.md), [M1030 Network Segmentation](/mitre/mitigations/M1030.md) and [M1035 Limit Access to Resource Over Network](/mitre/mitigations/M1035.md) are the ATT&CK mitigations (Inferred).

**Active Directory needed its own patch priority.** MS14-068 turned any domain user into a domain admin, and MS14-025 left old GPP passwords in place (Confirmed [25][19]). The library links [Authentication Cache Invalidation](/mitre/d3fend/authentication-cache-invalidation.md), [Credential Hardening](/mitre/d3fend/credential-hardening.md) and [Credential Rotation](/mitre/d3fend/credential-rotation.md) to T1558, and [Configuration Inventory](/mitre/d3fend/configuration-inventory.md) and [Restore Configuration](/mitre/d3fend/restore-configuration.md) to T1552.006 (Demonstrated [123]); [M1015 Active Directory Configuration](/mitre/mitigations/M1015.md) and [M1026 Privileged Account Management](/mitre/mitigations/M1026.md) are the ATT&CK mitigations (Inferred).

**Destructive and encrypting malware needed backups out of reach.** TA14-353A's tools overwrote drives and boot records, and TA14-295A's ransomware encrypted files (Confirmed [71][91]). The library links [Restore File](/mitre/d3fend/restore-file.md), [File Integrity Monitoring](/mitre/d3fend/file-integrity-monitoring.md) and [Decoy File](/mitre/d3fend/decoy-file.md) to T1486 and [Disk Partitioning](/mitre/d3fend/disk-partitioning.md) to T1561.002, and nothing to T1485 or T1021.002 (Demonstrated [123]); [M1053 Data Backup](/mitre/mitigations/M1053.md) is the ATT&CK mitigation (Inferred).

**Phishing and watering holes reached industrial and government networks.** Havex, the steel mill, Putter Panda and Sandworm's OLE attack all began with email or a compromised website (Confirmed [51][94][44][20]). The library links [Email Filtering](/mitre/d3fend/email-filtering.md), [File Analysis](/mitre/d3fend/file-analysis.md), [Dynamic Analysis](/mitre/d3fend/dynamic-analysis.md) and [Sender Reputation Analysis](/mitre/d3fend/sender-reputation-analysis.md) to T1566.001, and [URL Analysis](/mitre/d3fend/url-analysis.md) and [URL Reputation Analysis](/mitre/d3fend/url-reputation-analysis.md) to T1189 (Demonstrated [123]); [M1017 User Training](/mitre/mitigations/M1017.md) and [M1021 Restrict Web-Based Content](/mitre/mitigations/M1021.md) are the ATT&CK mitigations (Inferred).

**Internet-facing control systems needed to come off the internet.** BlackEnergy reached internet-connected HMIs, including through a GE Cimplicity flaw exploited from at least January 2012 (Confirmed [54]). The library links [Inbound Traffic Filtering](/mitre/d3fend/inbound-traffic-filtering.md), [Network Traffic Signature Analysis](/mitre/d3fend/network-traffic-signature-analysis.md) and [Database Query String Analysis](/mitre/d3fend/database-query-string-analysis.md) to T1190 (Demonstrated [123]); [M1030 Network Segmentation](/mitre/mitigations/M1030.md) and [M1037 Filter Network Traffic](/mitre/mitigations/M1037.md) are the ATT&CK mitigations (Inferred).

**Logging decided what could be learned.** Most of ICS-CERT's 245 incidents had an unknown access vector (Confirmed [95]). [M1047 Audit](/mitre/mitigations/M1047.md) is the ATT&CK mitigation, and the [incident response reference](/INCIDENT_RESPONSE_REFERENCE.md) covers the process side (Inferred).

## Part 12: MITRE mappings

No 2014 record opened here carries an ATT&CK id, because ATT&CK was released publicly in May 2015; every binding below is a later mapping (Confirmed [117]; Inferred for the binding). Every Enterprise binding is either a technique ATT&CK lists for an object it ties to a 2014 report or event (G0001 Axiom, G0012 Darkhotel, G0022 APT3, G0027 Threat Group-3390, G0032 Lazarus Group, G0034 Sandworm Team, G0035 Dragonfly, G0130 Ajax Security Team, S0016 P2P ZeuS, S0019 Regin, S0022 Uroburos, S0089 BlackEnergy, S0409 Machete, and the technique pages T1190 and T1212), or this study's mapping of a behavior a source describes. Every id was checked against the library's data files (`data/attack/technique_profiles.jsonl`, `group_to_technique.jsonl`, `software_to_technique.jsonl`, `groups.jsonl`, `software.jsonl`, `campaigns.jsonl`, `technique_to_d3fend.jsonl`, `data/attack/ics/` and `data/weaknesses/`) and against the generated pages under `mitre/` on 12 and 13 November 2026 (Demonstrated [121][122][123][124]). Names and tactics are those of ATT&CK v20.0 as the library carries them, including the v20.0 tactics stealth and defense-impairment (Demonstrated [121]).

The Basis column says how strong each tie is, as in the [2016 chronicle](/case-studies/CHRONICLE_2016.md). **Listed** means ATT&CK itself lists the id for the object or prints the 2014 example on the technique page. **Described** means a primary source describes the behavior and this study assigns the id. **Reported** means only a Reported source ties the behavior to 2014. **Inferred** means the mapping rests on this study's reading. Caveats on the Listed rows: Lazarus Group's entries cite Novetta 2016 and US-CERT 2018, not 2014 records [72]; Dragonfly's Enterprise entries and P2P ZeuS's entry were not traced to their citations [121]; APT3's 2014 exploit rests on a FireEye post that was not opened [48].

### ATT&CK Enterprise techniques

| Id | Name (ATT&CK v20.0) | Tactic(s) | Basis | Dated event or report | Sources |
|---|---|---|---|---|---|
| [`T1585.001`](/mitre/techniques/T1585-001.md) | Social Media Accounts | resource-development | Reported (G0059 lists it; the 2014 tie rests on eWeek) | Newscaster's fake personas (28 May) | [67][121] |
| [`T1566`](/mitre/techniques/T1566.md) | Phishing | initial-access | Listed (G0001); Described | Group 72 (Talos, 14 Oct); Havex phishing (Jun); GameOver Zeus spam and phishing (TA14-150A, 2 Jun); the steel mill's spear-phishing (BSI; Inferred for the mapping) | [47][46][51][90][94] |
| [`T1566.001`](/mitre/techniques/T1566-001.md) | Spearphishing Attachment | initial-access | Listed (G0034, G0035); Described | Sandworm's CVE-2014-4114 PowerPoint files (Jun to Oct; MS14-060, 14 Oct); Havex phishing (Jun); Putter Panda's targeted email (9 Jun); ransomware attachments (TA14-295A, 22 Oct) | [21][20][51][121][44][91] |
| [`T1566.003`](/mitre/techniques/T1566-003.md) | Spearphishing via Service | initial-access | Listed (G0130) | Saffron Rose (13 May) | [66][121] |
| [`T1189`](/mitre/techniques/T1189.md) | Drive-by Compromise | initial-access | Listed (G0001, G0012, G0035); Described | Group 72 (14 Oct); Darkhotel (10 Nov); Havex watering holes (Jun); Dragonfly's Lightsout kit (30 Jun); Epic Turla watering holes (7 Aug); drive-by ransomware (TA14-295A) | [46][61][51][52][57][91] |
| [`T1190`](/mitre/techniques/T1190.md) | Exploit Public-Facing Application | initial-access | Listed (technique page cites CVE-2014-7169); Described | Shellshock (24 to 25 Sep); Drupal CVE-2014-3704 attacks within hours (15 Oct); BlackEnergy against internet-connected HMIs through CVE-2014-0751 (8 Oct) | [30][29][39][54] |
| [`T1195.002`](/mitre/techniques/T1195-002.md) | Compromise Software Supply Chain | initial-access | Listed (G0035); Described | Havex installers trojanized on three ICS vendor sites (25 to 27 Jun); Dragonfly's compromised update sites (30 Jun) | [51][52][121] |
| [`T1199`](/mitre/techniques/T1199.md) | Trusted Relationship | initial-access | Described | Home Depot, through a third-party vendor's account (6 Nov); Target's HVAC vendor (Reported) | [79][2] |
| [`T1078`](/mitre/techniques/T1078.md) | Valid Accounts | stealth, persistence, privilege-escalation, initial-access | Described | eBay employee credentials (Feb to Mar); Home Depot vendor user name and password (6 Nov) | [73][79] |
| [`T1078.004`](/mitre/techniques/T1078-004.md) | Cloud Accounts | stealth, persistence, privilege-escalation, initial-access | Inferred | Celebrity Apple accounts taken through user names, passwords and security questions (2 Sep) | [75] |
| [`T1133`](/mitre/techniques/T1133.md) | External Remote Services | persistence, initial-access | Described | Backoff actors log in through remote-desktop applications (TA14-212A, 31 Jul) | [85] |
| [`T1203`](/mitre/techniques/T1203.md) | Exploitation for Client Execution | execution | Listed (G0034, G0022); Described | CVE-2014-4114 (G0034); CVE-2014-1776 (G0022, Reported; MS14-021, 1 May); IE CVE-2014-0322 (14 Feb); Putter Panda's Reader and Office exploits (9 Jun) | [21][48][18][5][44] |
| [`T1059.004`](/mitre/techniques/T1059-004.md) | Unix Shell | execution | Inferred | Shellshock's injected Bash commands (24 Sep) | [28][122] |
| [`T1543.003`](/mitre/techniques/T1543-003.md) | Windows Service | persistence, privilege-escalation | Listed (G0032) | Sony toolset (19 Dec), per ATT&CK's later citations | [72][71] |
| [`T1068`](/mitre/techniques/T1068.md) | Exploitation for Privilege Escalation | privilege-escalation | Listed (G0027); Described | CVE-2014-6324 (MS14-068, 18 Nov); Epic Turla's CVE-2013-5065 zero-day (7 Aug) | [118][121][25][57] |
| [`T1548.002`](/mitre/techniques/T1548-002.md) | Bypass User Account Control | privilege-escalation | Listed (S0089) | BlackEnergy 3 (F-Secure, summer 2014) | [55][56] |
| [`T1014`](/mitre/techniques/T1014.md) | Rootkit | stealth | Listed (S0022) | Snake/Uroburos in Epic Turla (7 Aug) | [57][121] |
| [`T1564.004`](/mitre/techniques/T1564-004.md) | NTFS File Attributes | stealth | Listed (S0019) | Regin (24 Nov) | [65] |
| [`T1564.005`](/mitre/techniques/T1564-005.md) | Hidden File System | stealth | Listed (S0019) | Regin (24 Nov) | [63][65] |
| [`T1553.002`](/mitre/techniques/T1553-002.md) | Code Signing | defense-impairment | Listed (G0012) | Darkhotel's abuse of at least ten CAs (10 Nov) | [61] |
| [`T1553.006`](/mitre/techniques/T1553-006.md) | Code Signing Policy Modification | defense-impairment | Listed (S0089) | BlackEnergy 3's driver-signing bypass (summer 2014) | [55][56] |
| [`T1110`](/mitre/techniques/T1110.md) | Brute Force | credential-access | Described | Backoff's brute-forced remote-desktop logins (31 Jul) | [85] |
| [`T1110.003`](/mitre/techniques/T1110-003.md) | Password Spraying | credential-access | Listed (G0032); Described | Sony's SMB worm guessing passwords (TA14-353A, 19 Dec) | [72][71] |
| [`T1212`](/mitre/techniques/T1212.md) | Exploitation for Credential Access | credential-access | Listed (technique page cites MS14-068) | MS14-068 (18 Nov) | [118][25] |
| [`T1558`](/mitre/techniques/T1558.md) | Steal or Forge Kerberos Tickets | credential-access | Described | Forged Kerberos ticket accepted as domain admin (MS14-068, 18 Nov) | [25] |
| [`T1552.006`](/mitre/techniques/T1552-006.md) | Group Policy Preferences | credential-access | Described | GPP passwords under targeted attack (MS14-025, 13 May) | [19] |
| [`T1557`](/mitre/techniques/T1557.md) | Adversary-in-the-Middle | credential-access, collection | Described (CCS injection); Inferred (POODLE) | CVE-2014-0224 (5 Jun); POODLE (14 Oct) | [37][119][34] |
| [`T1040`](/mitre/techniques/T1040.md) | Network Sniffing | credential-access, discovery | Listed (S0019) | Regin (24 Nov) | [65] |
| [`T1056.001`](/mitre/techniques/T1056-001.md) | Keylogging | collection, credential-access | Listed (G0012, S0409); Described | Darkhotel (10 Nov); El Machete (20 Aug); Backoff (31 Jul) | [61][60][85] |
| [`T1600`](/mitre/techniques/T1600.md) | Weaken Encryption | defense-impairment | Inferred | POODLE's protocol downgrade, through CAPEC-620 (14 Oct) | [31][122] |
| [`T1021.002`](/mitre/techniques/T1021-002.md) | SMB/Windows Admin Shares | lateral-movement | Listed (G0032, S0019); Described | Regin's admin shares (24 Nov); Sony's SMB worm (19 Dec) | [63][65][72][71] |
| [`T1113`](/mitre/techniques/T1113.md) | Screen Capture | collection | Listed (S0409) | El Machete (20 Aug) | [60] |
| [`T1123`](/mitre/techniques/T1123.md) | Audio Capture | collection | Listed (S0409) | El Machete (20 Aug) | [60] |
| [`T1125`](/mitre/techniques/T1125.md) | Video Capture | collection | Listed (S0409) | El Machete's webcam photos (20 Aug) | [60] |
| [`T1115`](/mitre/techniques/T1115.md) | Clipboard Data | collection | Listed (S0409) | El Machete (20 Aug) | [60] |
| [`T1052.001`](/mitre/techniques/T1052-001.md) | Exfiltration over USB | exfiltration | Listed (S0409) | El Machete copies files to USB (20 Aug) | [60] |
| [`T1071.001`](/mitre/techniques/T1071-001.md) | Web Protocols | command-and-control | Described | Backoff's HTTP POST command and control (31 Jul) | [85] |
| [`T1001.001`](/mitre/techniques/T1001-001.md) | Junk Data | command-and-control | Listed (S0016) | GameOver Zeus, disrupted 2 Jun | [121][88] |
| [`T1571`](/mitre/techniques/T1571.md) | Non-Standard Port | command-and-control | Listed (G0032) | Sony toolset (19 Dec), per ATT&CK's later citations | [72] |
| [`T1485`](/mitre/techniques/T1485.md) | Data Destruction | impact | Listed (G0032); Described | Sony's destructive malware (late Nov; 19 Dec) | [72][70][71] |
| [`T1561.001`](/mitre/techniques/T1561-001.md) | Disk Content Wipe | impact | Listed (G0032); Described | Hard-drive tool overwriting up to four drives (TA14-353A) | [72][71] |
| [`T1561.002`](/mitre/techniques/T1561-002.md) | Disk Structure Wipe | impact | Listed (G0032); Described | Master boot record overwritten (TA14-353A) | [72][71] |
| [`T1491.001`](/mitre/techniques/T1491-001.md) | Internal Defacement | impact | Listed (G0032) | Sony (Nov), per ATT&CK's later citations | [72] |
| [`T1486`](/mitre/techniques/T1486.md) | Data Encrypted for Impact | impact | Described | CryptoLocker (disrupted 2 Jun); crypto ransomware (TA14-295A, 22 Oct) | [88][91] |
| [`T1498.002`](/mitre/techniques/T1498-002.md) | Reflection Amplification | impact | Described | NTP monlist amplification (13 Jan) | [4] |

Left out on purpose: APT1's techniques, which cite Mandiant's 2013 report and are not bound to 2014 here [121]; Putter Panda's own ATT&CK entries, which the library does not list for the behaviors CrowdStrike describes, so its behaviors are bound only as Described rows above [121][44]; the Newscaster, Cleaver, KHNP and APT28 entries beyond T1585.001, which rest on Reported sources [67][68][69][58]; Careto, which has no ATT&CK object [59]; the retail POS memory scraping itself, for which no technique fits the sources' plain description without guessing [85]; Heartbleed's memory read, bound here only through CAPEC-540 [13]; Masque Attack, an ATT&CK for Mobile matter not bound here [40]; MtGox's coin loss, whose cause is the company's belief [7]; and any technique for JPMorgan, CHS and Yahoo, whose primaries describe no intrusion method [76][49][86].

### ATT&CK for ICS

The library has no generated pages for ICS techniques, so the ids are plain text; names and tactics are those in `data/attack/ics/` (Demonstrated [121][124]).

| Id | Name (ATT&CK for ICS v20.0) | Tactic(s) | Basis | Dated event or report | Sources |
|---|---|---|---|---|---|
| T0817 | Drive-by Compromise | initial-access | Listed (G0035); Described | Havex watering-hole redirects (25 to 27 Jun) | [121][51] |
| T0862 | Supply Chain Compromise | initial-access | Listed (G0035, S0093) | Trojanized ICS vendor installers (25 to 27 Jun) | [53][51] |
| T0865 | Spearphishing Attachment | initial-access | Listed (S0093) | Havex phishing (Symantec, 30 Jun) | [53][52] |
| T0863 | User Execution | execution | Listed (S0093) | Havex installers run by users (Jun) | [53] |
| T0861 | Point & Tag Identification | collection | Listed (S0093); Described | OPC server and tag enumeration (Jun) | [53][50] |
| T0846 | Remote System Discovery | discovery | Listed (S0093) | Havex OPC scanning (Jun) | [53][50] |
| T0888 | Remote System Information Discovery | discovery | Listed (S0093) | Havex OPC scanning (Jun) | [53][50] |
| T0802 | Automated Collection | collection | Listed (S0093) | Havex OPC payload (Jun) | [53][50] |
| T0814 | Denial of Service | inhibit-response-function | Listed (S0093); Described | Some OPC platforms crashed by the scan (Jun) | [53][50] |
| T0883 | Internet Accessible Device | initial-access | Described | BlackEnergy against internet-connected HMIs (8 Oct) | [54] |
| T0819 | Exploit Public-Facing Application | initial-access | Described | GE Cimplicity CVE-2014-0751 exploited since January 2012 (8 Oct alert) | [54] |
| T0879 | Damage to Property | impact | Inferred | German steel mill blast furnace (BSI, 2014) | [94] |
| T0827 | Loss of Control | impact | Inferred | Blast furnace could not be shut down in a controlled way (BSI) | [94] |
| T0826 | Loss of Availability | impact | Inferred | Control components and installations failing (BSI) | [94] |

ATT&CK's S0093 page lists eight ICS techniques, including T0814, and the library's ICS software data counts eight (Confirmed [53]; Demonstrated [121]). The library's ICS data also maps G0034 to T0819 for later events; this study binds T0819 to 2014 only as Described from the ICS-CERT alert (Demonstrated [121]).

### ATT&CK groups, software and campaigns

| Object | Id | Binding | Sources |
|---|---|---|---|
| APT1 | [G0006](/mitre/groups/G0006.md) | Context: attributed to Unit 61398, the unit named in the May 2014 indictment; its techniques cite 2013 records and are not bound here | [121][42][43] |
| Putter Panda | [G0024](/mitre/groups/G0024.md) | Context: CrowdStrike, 9 Jun 2014; behaviors bound as Described | [44][45][121] |
| Axiom | [G0001](/mitre/groups/G0001.md) | Bound: T1189 and T1566 cite Talos, 14 Oct 2014 | [47][46] |
| APT3 | [G0022](/mitre/groups/G0022.md) | Bound (Reported): T1203 cites CVE-2014-1776 and FireEye, 26 Apr 2014 | [48] |
| Threat Group-3390 | [G0027](/mitre/groups/G0027.md) | Bound: T1068 lists its use of CVE-2014-6324; the date of use was not checked | [118][121] |
| Dragonfly | [G0035](/mitre/groups/G0035.md) | Bound with a caveat: Enterprise T1189, T1195.002 (citations not opened) and ICS T0817, T0862 | [121][52] |
| Backdoor.Oldrea (Havex) | [S0093](/mitre/software/S0093.md) | Bound: eight ICS techniques citing Symantec and F-Secure, June and July 2014 | [53] |
| Trojan.Karagany | [S0094](/mitre/software/S0094.md) | Context: named in Symantec's Dragonfly report | [52][121] |
| Sandworm Team | [G0034](/mitre/groups/G0034.md) | Bound: T1203 and T1566.001 cite CVE-2014-4114 | [21][121] |
| BlackEnergy | [S0089](/mitre/software/S0089.md) | Bound: T1548.002 and T1553.006 (F-Secure, 2014) | [55][56] |
| Turla; Epic; Uroburos | [G0010](/mitre/groups/G0010.md); [S0091](/mitre/software/S0091.md); [S0022](/mitre/software/S0022.md) | Bound: S0022's T1014 (Kaspersky, 7 Aug 2014); G0010 and S0091 context | [57][121] |
| APT28 | [G0007](/mitre/groups/G0007.md) | Context only (Reported): operations of 2014 to 2018 in a 2018 indictment | [58] |
| Regin | [S0019](/mitre/software/S0019.md) | Bound: four of its techniques, citing Kaspersky, 24 Nov 2014 | [65][63] |
| Machete | [G0095](/mitre/groups/G0095.md); [S0409](/mitre/software/S0409.md) | Bound: S0409's six techniques (Kaspersky, 20 Aug 2014) | [60][121] |
| Darkhotel | [G0012](/mitre/groups/G0012.md) | Bound: T1189, T1553.002, T1056.001 (Kaspersky, 10 Nov 2014) | [61] |
| Ajax Security Team | [G0130](/mitre/groups/G0130.md) | Bound: T1566.003 cites Saffron Rose | [66][121] |
| Magic Hound | [G0059](/mitre/groups/G0059.md) | Reported: alias Newscaster; T1585.001 | [67][121] |
| Cleaver | [G0003](/mitre/groups/G0003.md) | Context only (Reported): Operation Cleaver, December 2014 | [68] |
| Kimsuky | [G0094](/mitre/groups/G0094.md) | Context only (Reported): assessed responsible for the 2014 KHNP compromise | [69] |
| Lazarus Group | [G0032](/mitre/groups/G0032.md) | Bound with a caveat: alias Guardians of Peace; eight techniques whose citations are 2016 and 2018 records | [72][70][71] |
| P2P ZeuS | [S0016](/mitre/software/S0016.md) | Bound with a caveat: alias Gameover ZeuS; T1001.001 (citation not opened) | [121][88][90] |
| njRAT | [S0385](/mitre/software/S0385.md) | Context: Microsoft's No-IP action, 30 Jun 2014 | [92] |
| Emotet; Dridex; Dyre | [S0367](/mitre/software/S0367.md); [S0384](/mitre/software/S0384.md); [S0024](/mitre/software/S0024.md) | Context: ATT&CK dates Emotet to June 2014 and Dridex to 2014; Dyre's 2014 date not opened | [121] |
| Carbanak | [G0008](/mitre/groups/G0008.md); [S0030](/mitre/software/S0030.md) | Context: against financial institutions since at least 2013 | [121] |
| Mimikatz | [S0002](/mitre/software/S0002.md) | Context only: page exists; 2014 date not opened | [124] |

No ATT&CK campaign object for a 2014 event in this record was found in the library's campaign data (Demonstrated [121]). The only campaign object with a 2014 first-seen date, [C0032](/mitre/campaigns/C0032.md), is tied to the Triton actors and to no 2014 primary opened here, so it is not bound (Demonstrated [121]). The library's ATT&CK data has no object for Careto, CryptoLocker, BlackShades or Backoff (Demonstrated [121]).

### CWE and CAPEC

The CWE column names the source of each id. Names are those in the library's CWE and CAPEC data, and every CAPEC listed has a page under `/mitre/capec/` (Demonstrated [122][124]). The library has no per-CWE generated pages, so CWE ids are plain text; the [CWE reference](/CWE_REFERENCE.md) is the library's entry point.

| CWE | Weakness (library name) | Basis | 2014 record | CAPEC |
|---|---|---|---|---|
| CWE-125 | Out-of-bounds Read | NVD [13] | Heartbleed CVE-2014-0160 (7 Apr) | [CAPEC-540](/mitre/capec/CAPEC-540.md) Overread Buffers (Inferred, through the library's CWE relation) |
| CWE-78 | Improper Neutralization of Special Elements used in an OS Command | NVD [28] | Shellshock CVE-2014-6271 (24 Sep) | [CAPEC-88](/mitre/capec/CAPEC-88.md) OS Command Injection (Inferred) |
| CWE-310, CWE-329 | (CWE-310 is a category not in the library's CWE data); Generation of Predictable IV with CBC Mode | NVD (CWE-310); the CNA (CWE-329) [35] | POODLE CVE-2014-3566 (14 Oct) | [CAPEC-620](/mitre/capec/CAPEC-620.md) Drop Encryption Level (Inferred; the library relates it to CWE-757 and T1600) |
| CWE-295 | Improper Certificate Validation | NVD [6] | Apple CVE-2014-1266 (22 Feb) | None assigned |
| CWE-416 | Use After Free | NVD [5][17] | IE CVE-2014-0322 (Feb) and CVE-2014-1776 (Apr) | None assigned |
| CWE-89 | Improper Neutralization of Special Elements used in an SQL Command | NVD [38] | Drupal CVE-2014-3704 (Oct) | [CAPEC-66](/mitre/capec/CAPEC-66.md) SQL Injection (the library relates it to CWE-89) |
| CWE-94 | Improper Control of Generation of Code | NVD [24][22] | Schannel CVE-2014-6321 (Nov); win32k CVE-2014-4148 (Oct) | None assigned |
| CWE-20 | Improper Input Validation | NVD [4] | NTP CVE-2013-5211 (Jan) | None assigned |
| none bound | (NVD-CWE-noinfo) | NVD [21] | OLE CVE-2014-4114 (Oct) | None |
| none bound | (credentials and Kerberos) | Library data | MS14-068; MS14-025; Sony's SMB worm; eBay and Home Depot | [CAPEC-652](/mitre/capec/CAPEC-652.md) Use of Known Kerberos Credentials (on T1558); [CAPEC-639](/mitre/capec/CAPEC-639.md) Probe System Files (on T1552.006); [CAPEC-565](/mitre/capec/CAPEC-565.md) Password Spraying (on T1110.003); [CAPEC-112](/mitre/capec/CAPEC-112.md) Brute Force (on T1110); [CAPEC-561](/mitre/capec/CAPEC-561.md) Windows Admin Shares with Stolen Credentials (on T1021.002); [CAPEC-560](/mitre/capec/CAPEC-560.md) Use of Known Domain Credentials (on T1078); [CAPEC-568](/mitre/capec/CAPEC-568.md) Capture Credentials via Keylogger (on T1056.001) |
| none bound | (phishing, interception and supply chain) | Library data | Havex; Sandworm; Saffron Rose; CCS injection and POODLE | [CAPEC-98](/mitre/capec/CAPEC-98.md) Phishing (on T1566); [CAPEC-163](/mitre/capec/CAPEC-163.md) Spear Phishing (on T1566.001 and T1566.003); [CAPEC-94](/mitre/capec/CAPEC-94.md) Adversary in the Middle (AiTM) (on T1557); [CAPEC-186](/mitre/capec/CAPEC-186.md) Malicious Software Update (on T1195.002) |
| none bound | (stealth and amplification) | Library data | Uroburos; Darkhotel; NTP DDoS | [CAPEC-552](/mitre/capec/CAPEC-552.md) Install Rootkit (on T1014); [CAPEC-68](/mitre/capec/CAPEC-68.md) Subvert Code-signing Facilities (on T1553.002); [CAPEC-490](/mitre/capec/CAPEC-490.md) Amplification (on T1498.002) |

### D3FEND countermeasures

The technique-to-countermeasure links come from the library's D3FEND data (version 1.6.0); pairing them with the 2014 record is this study's reading (Demonstrated [123]; Inferred). Every page exists under `/mitre/d3fend/` (Demonstrated [124]).

| Technique or event from the record | D3FEND countermeasures (D3FEND tactic) | 2014 analogue |
|---|---|---|
| T1212, T1203, T1068 | [Software Update](/mitre/d3fend/software-update.md) (Harden, on T1212); [Software Inventory](/mitre/d3fend/software-inventory.md) (Model, on T1212); [Restore Software](/mitre/d3fend/restore-software.md) (Restore, on T1212); [Process Segment Execution Prevention](/mitre/d3fend/process-segment-execution-prevention.md) (Harden); [Segment Address Offset Randomization](/mitre/d3fend/segment-address-offset-randomization.md) (Harden); [Stack Frame Canary Validation](/mitre/d3fend/stack-frame-canary-validation.md) (Harden); [Memory Boundary Tracking](/mitre/d3fend/memory-boundary-tracking.md) (Detect) | MS14-068 [25]; IE and OLE zero-days [5][16][20] |
| T1195.002 | [Software Inventory](/mitre/d3fend/software-inventory.md) (Model); [Software Update](/mitre/d3fend/software-update.md) (Harden); [Restore Software](/mitre/d3fend/restore-software.md) (Restore) | Havex installers [51] |
| T1190 | [Inbound Traffic Filtering](/mitre/d3fend/inbound-traffic-filtering.md) (Isolate); [Network Traffic Signature Analysis](/mitre/d3fend/network-traffic-signature-analysis.md) (Detect); [Database Query String Analysis](/mitre/d3fend/database-query-string-analysis.md) (Detect); [Client-server Payload Profiling](/mitre/d3fend/client-server-payload-profiling.md) (Detect) | Shellshock [29]; Drupal [39]; BlackEnergy HMIs [54] |
| T1557, T1189 | [Network Traffic Signature Analysis](/mitre/d3fend/network-traffic-signature-analysis.md) (Detect); [Network Traffic Filtering](/mitre/d3fend/network-traffic-filtering.md) (Isolate); [URL Analysis](/mitre/d3fend/url-analysis.md) and [URL Reputation Analysis](/mitre/d3fend/url-reputation-analysis.md) (Detect, on T1189) | CCS injection and POODLE [37][34]; watering holes [51][57] |
| T1558 | [Credential Rotation](/mitre/d3fend/credential-rotation.md) (Harden); [Credential Revocation](/mitre/d3fend/credential-revocation.md) (Evict); [Authentication Cache Invalidation](/mitre/d3fend/authentication-cache-invalidation.md) (Evict); [Credential Hardening](/mitre/d3fend/credential-hardening.md) (Harden); [Multi-factor Authentication](/mitre/d3fend/multi-factor-authentication.md) (Harden); [Reissue Credential](/mitre/d3fend/reissue-credential.md) (Restore) | MS14-068 [25] |
| T1552.006 | [Configuration Inventory](/mitre/d3fend/configuration-inventory.md) (Model); [Restore Configuration](/mitre/d3fend/restore-configuration.md) (Restore); [Access Modeling](/mitre/d3fend/access-modeling.md) (Model) | MS14-025 [19] |
| T1566.001 | [Email Filtering](/mitre/d3fend/email-filtering.md) (Isolate); [File Analysis](/mitre/d3fend/file-analysis.md) (Detect); [Dynamic Analysis](/mitre/d3fend/dynamic-analysis.md) (Detect); [Sender Reputation Analysis](/mitre/d3fend/sender-reputation-analysis.md) (Detect) | Sandworm [20]; Putter Panda [44]; ransomware [91] |
| T1199, T1078 | [Connection Attempt Analysis](/mitre/d3fend/connection-attempt-analysis.md) (Detect); [Session Termination](/mitre/d3fend/session-termination.md) (Evict); [Remote Terminal Session Detection](/mitre/d3fend/remote-terminal-session-detection.md) (Detect); [Account Locking](/mitre/d3fend/account-locking.md) (Evict); [User Account Permissions](/mitre/d3fend/user-account-permissions.md) (Isolate); [Access Modeling](/mitre/d3fend/access-modeling.md) (Model) | Home Depot [79]; eBay [73]; Target (Reported) [2] |
| T1110.003 | [Strong Password Policy](/mitre/d3fend/strong-password-policy.md) (Harden); [Change Default Password](/mitre/d3fend/change-default-password.md) (Harden); [Multi-factor Authentication](/mitre/d3fend/multi-factor-authentication.md) (Harden); [Connection Attempt Analysis](/mitre/d3fend/connection-attempt-analysis.md) (Detect) | Sony's SMB worm [71]; Backoff's brute force [85] |
| T1486, T1561.002 | [Restore File](/mitre/d3fend/restore-file.md) (Restore); [File Integrity Monitoring](/mitre/d3fend/file-integrity-monitoring.md) (Detect); [Decoy File](/mitre/d3fend/decoy-file.md) (Deceive); [Disk Partitioning](/mitre/d3fend/disk-partitioning.md) (Evict, on T1561.002) | CryptoLocker [88][91]; Sony wiper [71] |
| T1498.002 | [Inbound Traffic Filtering](/mitre/d3fend/inbound-traffic-filtering.md) (Isolate); [Inbound Session Volume Analysis](/mitre/d3fend/inbound-session-volume-analysis.md) (Detect); [Network Traffic Filtering](/mitre/d3fend/network-traffic-filtering.md) (Isolate) | NTP amplification [4] |
| T1056.001 | [Input Device Analysis](/mitre/d3fend/input-device-analysis.md) (Detect); [IO Port Restriction](/mitre/d3fend/io-port-restriction.md) (Isolate) | Backoff [85]; Darkhotel [61]; El Machete [60] |
| T1014 | [File Integrity Monitoring](/mitre/d3fend/file-integrity-monitoring.md) (Detect); [Firmware Verification](/mitre/d3fend/firmware-verification.md) (Detect) | Uroburos [57] |
| The year's protocol failures | [Message Encryption](/mitre/d3fend/message-encryption.md) and [Certificate Pinning](/mitre/d3fend/certificate-pinning.md) (study's pairing; the library maps Message Encryption only to this study's Havex ICS ids (T0861, T0846, T0888, T0802), not to any of its Enterprise ids) | Heartbleed, POODLE, goto fail [11][34][6] |

The library links T1566, T1021.002, T1485, T1553.002, T1059.004 and T1110 to no D3FEND countermeasure (Demonstrated [123]). ATT&CK mitigation pages exist for [M1051 Update Software](/mitre/mitigations/M1051.md), [M1050 Exploit Protection](/mitre/mitigations/M1050.md), [M1042 Disable or Remove Feature or Program](/mitre/mitigations/M1042.md), [M1041 Encrypt Sensitive Information](/mitre/mitigations/M1041.md), [M1021 Restrict Web-Based Content](/mitre/mitigations/M1021.md), [M1017 User Training](/mitre/mitigations/M1017.md), [M1053 Data Backup](/mitre/mitigations/M1053.md), [M1037 Filter Network Traffic](/mitre/mitigations/M1037.md), [M1030 Network Segmentation](/mitre/mitigations/M1030.md), [M1035 Limit Access to Resource Over Network](/mitre/mitigations/M1035.md), [M1032 Multi-factor Authentication](/mitre/mitigations/M1032.md), [M1027 Password Policies](/mitre/mitigations/M1027.md), [M1026 Privileged Account Management](/mitre/mitigations/M1026.md), [M1015 Active Directory Configuration](/mitre/mitigations/M1015.md), [M1016 Vulnerability Scanning](/mitre/mitigations/M1016.md) and [M1047 Audit](/mitre/mitigations/M1047.md) (Demonstrated [124]). US-CERT's advice to disable SSL 3.0 maps most closely to M1042, Drupal's restore-from-backup advice to M1053, Microsoft's GPP and Kerberos fixes to M1051 and M1015, and Backoff's remote-access advice to M1032 and M1035 (Inferred [34][39][19][25][85]).

### Navigator layer

The study's techniques are saved as two ATT&CK Navigator layers pinned to ATT&CK v20, in the format of the existing chronicle layers: the Enterprise layer [navigator/library-layers/chronicle-2014.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/chronicle-2014.json) (domain enterprise-attack: the 45 techniques of the Enterprise table under each tactic they carry in v20.0, 56 technique-tactic entries) and the ICS layer [navigator/case-studies/chronicle-2014-ics.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/case-studies/chronicle-2014-ics.json) (domain ics-attack: the 14 techniques of the ICS table), both described as curated case-study layers and not official MITRE mappings and listed on [the Navigator layers page](/navigator/index.md) (Demonstrated [125]). Scores show the basis, not severity, in the house scale set by the 2016 chronicle: 100 where an ATT&CK object or technique page prints the id (Listed), 70 where a primary source describes the behavior and this study assigns the id (Described), 50 where only a Reported source supports it, and 40 for an Inferred mapping. In the Enterprise layer 31 techniques score 100, T1199, T1078, T1133, T1110, T1558, T1552.006, T1557, T1071.001, T1486 and T1498.002 score 70, T1585.001 scores 50, and T1078.004, T1059.004 and T1600 score 40. In the ICS layer T0817, T0862, T0865, T0863, T0861, T0846, T0888, T0802 and T0814 score 100, T0883 and T0819 score 70, and T0879, T0827 and T0826 score 40. Each entry's comment names the source numbers in the Sources table below.

## Cross-cutting themes

**Shared infrastructure code failed in public, and the fixes were institutional.** OpenSSL, Bash and SSL 3.0 broke within six months; the same year brought a full-time bug-hunting team, an OpenSSL fork, a free certificate authority, an IETF statement and browsers that dropped a protocol (Confirmed [11][28][31][112][113][111][109][32]; Inferred for the reading).

**Card theft was routine, and Home Depot learned of its breach from others.** Home Depot learned of its breach from banks and law enforcement, Target's card window ran for nearly three weeks before it closed, and Backoff's Secret Service count ran past 1,000 businesses (Confirmed [77][1][85]).

**The state was named in court and at the podium.** The Unit 61398 indictment and the FBI's Sony statement were public state attributions by the US government in the same year (Confirmed [42][70]).

**Industrial systems were reached from the business side.** Havex came through vendor downloads, the steel mill through spear-phishing into the office network, and BlackEnergy through HMIs left on the internet (Confirmed [51][94][54]).

**Windows identity infrastructure was a target.** MS14-025 and MS14-068 were both under targeted attack, and the year's one KEV ransomware flag went to the GPP flaw (Confirmed [19][25][27]).

**Policy turned toward disclosure and governance.** CSF 1.0, the SEC's sweep and speech, FISMA 2014's seven-day notice to Congress and the chip-and-PIN order all date from 2014 (Confirmed [96][101][102][104][103]).

### What is overstated and what is understated

This section is the study's reading of the record (Inferred).

- **Overstated: the branded bugs as measured threats.** KEV added Heartbleed and Shellshock only in 2022 and never added POODLE, and TA14-290A called POODLE exploitation somewhat difficult because it needs a man-in-the-middle position; Heartbleed exploitation counts were not checked [13][28][35][34].
- **Overstated: the Senate Target report as an investigation.** It states that it is built on media reports and expert analyses, and its 'up to 110 million' is the sum of Target's two figures, about 40 million card accounts and up to 70 million people, which Target reports separately and which may overlap [2][1] (Inferred for the overlap).
- **Overstated: the company attributions.** CHS's "originating from China" and Yahoo's "state-sponsored actor" are the companies' beliefs, not government or court findings [49][86].
- **Overstated: the 2014 attribution behind the vendor reports.** Careto, Regin, Darkhotel, Dragonfly and Quedagh were named to a state, if at all, by later records [59][63][61][52][55].
- **Overstated: the precision of ATT&CK ids on 2014 events.** ATT&CK was public only from May 2015, and the Sony rows rest on Novetta's 2016 report and US-CERT's 2018 records [117][72].
- **Understated: MS14-068 and MS14-025.** Both were under targeted attack at release and let an authenticated domain user elevate privileges, yet neither was branded the way Heartbleed, Shellshock and POODLE were [25][19].
- **Understated: Havex's trojanized ICS vendor installers.** A software supply-chain compromise of control-system vendors in 2014 got far less attention than the year's card breaches, and ATT&CK lists it as T0862 [51][53].
- **Understated: the German steel mill.** BSI described physical damage to a blast furnace from a cyberattack, with no date or victim name [94].
- **Understated: the long tail.** Every one of KEV's 34 CVE-2014 entries was added on 3 November 2021 or later, and CVE-2014-6278 was added in October 2025 [27][29].
- **Understated: the gap between activity and disclosure.** Regin samples date to 2003, Careto to 2007, the BlackEnergy HMI campaign to 2011, and Yahoo's late-2014 theft was disclosed in 2016 [63][59][54][86].

### Discrepancies in the record

- **Target's numbers.** Target's 10-K gives about 40 million card accounts and contact data for up to 70 million people; the Senate staff report gives up to 110 million customers, the sum of Target's two figures, which Target reports separately and which may overlap (Confirmed [1][2]; Inferred for the overlap).
- **The Havex alert's date.** ICS-ALERT-14-176-02 was first published on 25 June, and Update A on 27 June (Confirmed [50][51]).
- **The BlackEnergy alert's updates.** The ICS-CERT page records an update on 10 December 2014; [Sandworm Operations](/case-studies/SANDWORM_OPERATIONS.md) records one on 17 October 2014. The alert went through several lettered revisions, and the two may both be right (Confirmed [54][126]; Inferred for the reconciliation).
- **Windows XP's end.** Microsoft's lifecycle page lists 4/9/2014 6:59:59 AM; read as UTC, as the 8:00:00 AM start times on the same page suggest, that is the last second of 8 April Pacific time and the early hours of 9 April in eastern US time zones, consistent with TA14-069A's 8 April (Confirmed [10][9]; Inferred for the reading).
- **The BSI report's date.** The report is dated November 2014; its PDF metadata gives 21 January 2015 (Confirmed [94]).
- **Home Depot's window.** The 8 September 8-K says April 2014 onward; the 18 September 8-K says April to September 2014 (Confirmed [77][78]).
- **CVE-2014-1776's dates.** Microsoft's advisory is dated 26 April, NVD published the record on 27 April and US-CERT's alert is dated 28 April (Confirmed [17][16]).
- **The indictment's dates.** The grand jury returned it on 1 May; the FBI announced it on 19 May (Confirmed [43][42]).
- **POODLE's dates.** Google and Mozilla posted on 14 October, OpenSSL and NVD on 15 October, and US-CERT on 17 October (Confirmed [31][32][33][35][34]).
- **eBay's dates.** The press release is dated 21 May and the 8-K exhibit was filed on 22 May (Confirmed [73][74]).

## Sources

Every external source was opened on 12 November 2026, and the library data checks were run on 12 and 13 November 2026, as the Opened column shows. All are checked as of 13 November 2026. Grade is the source's evidence grade as used in this study. Addresses shown as code rather than as links refuse automated link checkers (the NVD API queries and the sec.gov addresses of the company filings and the SEC's examination alert and speech); copy them into a browser to open them.

| # | Source | URL | Opened | Grade |
|---|---|---|---|---|
| 1 | Target Corporation, Form 10-K for fiscal 2013, filed 14 Mar 2014 | `https://www.sec.gov/Archives/edgar/data/27419/000002741914000014/tgt-20140201x10k.htm` | 2026-11-12 | Confirmed (the company's account) |
| 2 | US Senate Committee on Commerce, Science and Transportation, majority staff, A Kill Chain Analysis of the 2013 Target Data Breach, 26 Mar 2014 | https://www.commerce.senate.gov/wp-content/uploads/media/doc/2014%200325%20Target%20Kill%20Chain%20Analysis.pdf | 2026-11-12 | Confirmed (the report); Reported (details it draws from media reports) |
| 3 | US-CERT (CISA archive), TA14-002A, Malware Targeting Point of Sale Systems, 2 Jan 2014 | https://www.cisa.gov/news-events/alerts/2014/01/02/malware-targeting-point-sale-systems | 2026-11-12 | Confirmed |
| 4 | US-CERT (CISA archive), NTP Amplification Attacks Using CVE-2013-5211, 13 Jan 2014 | https://www.cisa.gov/news-events/alerts/2014/01/13/ntp-amplification-attacks-using-cve-2013-5211 | 2026-11-12 | Confirmed |
| 5 | NVD, CVE-2014-0322 | https://nvd.nist.gov/vuln/detail/CVE-2014-0322 | 2026-11-12 | Confirmed |
| 6 | NVD, CVE-2014-1266 (detail page and API record) | https://nvd.nist.gov/vuln/detail/CVE-2014-1266 ; `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2014-1266` | 2026-11-12 | Confirmed |
| 7 | MtGox Co., Ltd., announcement of the application for civil rehabilitation, 28 Feb 2014 | https://www.mtgox.com/img/pdf/20140228-announcement_eng.pdf | 2026-11-12 | Confirmed (the company's account) |
| 8 | Mt. Gox trustee site, proceedings timeline | https://www.mtgox.com/ | 2026-11-12 | Confirmed |
| 9 | US-CERT (CISA archive), TA14-069A, Microsoft Ending Support for Windows XP and Office 2003, 10 Mar 2014 | https://www.cisa.gov/news-events/alerts/2014/03/10/microsoft-ending-support-windows-xp-and-office-2003 | 2026-11-12 | Confirmed |
| 10 | Microsoft Learn, Windows XP lifecycle | https://learn.microsoft.com/en-us/lifecycle/products/windows-xp | 2026-11-12 | Confirmed |
| 11 | OpenSSL, Security Advisory, 07 Apr 2014 (TLS heartbeat read overrun, CVE-2014-0160) | https://www.openssl.org/news/secadv/20140407.txt ; https://openssl-library.org/news/secadv/20140407.txt | 2026-11-12 | Confirmed |
| 12 | US-CERT (CISA archive), TA14-098A, OpenSSL Heartbleed Vulnerability (CVE-2014-0160), 8 Apr 2014 | https://www.cisa.gov/news-events/alerts/2014/04/08/openssl-heartbleed-vulnerability-cve-2014-0160 | 2026-11-12 | Confirmed |
| 13 | NVD, CVE-2014-0160 (API record) | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2014-0160` | 2026-11-12 | Confirmed |
| 14 | CERT/CC, Vulnerability Note VU#720951 | https://www.kb.cert.org/vuls/id/720951 | 2026-11-12 | Confirmed |
| 15 | Codenomicon, heartbleed.com | https://heartbleed.com/ | 2026-11-12 | Reported (the company's account of the discovery) |
| 16 | US-CERT (CISA archive), Microsoft Internet Explorer Use-After-Free Vulnerability Guidance, 28 Apr 2014 | https://www.cisa.gov/news-events/alerts/2014/04/28/microsoft-internet-explorer-use-after-free-vulnerability-guidance | 2026-11-12 | Confirmed |
| 17 | Microsoft, Security Advisory 2963983 | https://learn.microsoft.com/en-us/security-updates/securityadvisories/2014/2963983 | 2026-11-12 | Confirmed |
| 18 | Microsoft, Security Bulletin MS14-021, 1 May 2014 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2014/ms14-021 | 2026-11-12 | Confirmed |
| 19 | Microsoft, Security Bulletin MS14-025, 13 May 2014 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2014/ms14-025 | 2026-11-12 | Confirmed |
| 20 | Microsoft, Security Bulletin MS14-060, 14 Oct 2014 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2014/ms14-060 | 2026-11-12 | Confirmed |
| 21 | NVD, CVE-2014-4114 | https://nvd.nist.gov/vuln/detail/CVE-2014-4114 | 2026-11-12 | Confirmed |
| 22 | NVD, CVE-2014-4148 | https://nvd.nist.gov/vuln/detail/CVE-2014-4148 | 2026-11-12 | Confirmed |
| 23 | Microsoft, Security Bulletin MS14-066, 11 Nov 2014 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2014/ms14-066 | 2026-11-12 | Confirmed |
| 24 | NVD, CVE-2014-6321 | https://nvd.nist.gov/vuln/detail/CVE-2014-6321 | 2026-11-12 | Confirmed |
| 25 | Microsoft, Security Bulletin MS14-068, 18 Nov 2014 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2014/ms14-068 | 2026-11-12 | Confirmed |
| 26 | NVD, CVE-2014-6324 (API record) | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2014-6324` | 2026-11-12 | Confirmed |
| 27 | CISA, Known Exploited Vulnerabilities catalog (JSON feed, catalog 2026.11.10) | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | 2026-11-12 | Confirmed |
| 28 | NVD, CVE-2014-6271 (detail page and API record) | https://nvd.nist.gov/vuln/detail/CVE-2014-6271 ; `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2014-6271` | 2026-11-12 | Confirmed |
| 29 | US-CERT (CISA archive), TA14-268A, GNU Bourne-Again Shell (Bash) Shellshock Vulnerability, 25 Sep 2014 (revised 26 and 30 Sep) | https://www.cisa.gov/news-events/alerts/2014/09/25/gnu-bourne-again-shell-bash-shellshock-vulnerability-cve-2014-6271-cve-2014-7169-cve-2014-7186-cve ; https://www.cisa.gov/news-events/alerts/2014/09/25/gnu-bourne-again-shell-bash-shellshock-vulnerability-cve-2014-6271 | 2026-11-12 | Confirmed |
| 30 | MITRE ATT&CK, T1190 Exploit Public-Facing Application | https://attack.mitre.org/techniques/T1190/ | 2026-11-12 | Confirmed |
| 31 | Google Security Blog, This POODLE bites: exploiting the SSL 3.0 fallback, 14 Oct 2014 | https://security.googleblog.com/2014/10/this-poodle-bites-exploiting-ssl-30.html | 2026-11-12 | Confirmed |
| 32 | Mozilla Security Blog, The POODLE Attack and the End of SSL 3.0, 14 Oct 2014 | https://blog.mozilla.org/security/2014/10/14/the-poodle-attack-and-the-end-of-ssl-3-0/ | 2026-11-12 | Confirmed |
| 33 | OpenSSL, Security Advisory, 15 Oct 2014 | https://openssl-library.org/news/secadv/20141015.txt | 2026-11-12 | Confirmed |
| 34 | US-CERT (CISA archive), TA14-290A, SSL 3.0 Protocol Vulnerability and POODLE Attack, 17 Oct 2014 (revised Dec 2014) | https://www.cisa.gov/news-events/alerts/2014/10/17/ssl-30-protocol-vulnerability-and-poodle-attack | 2026-11-12 | Confirmed |
| 35 | NVD, CVE-2014-3566 (API record) | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2014-3566` | 2026-11-12 | Confirmed |
| 36 | IETF (RFC Editor), RFC 7568, Deprecating Secure Sockets Layer Version 3.0, Jun 2015 (with RFC 7507, Apr 2015) | https://www.rfc-editor.org/rfc/rfc7568.txt | 2026-11-12 | Confirmed |
| 37 | OpenSSL, Security Advisory, 05 Jun 2014 (CVE-2014-0224) | https://openssl-library.org/news/secadv/20140605.txt | 2026-11-12 | Confirmed |
| 38 | NVD, CVE-2014-3704 (detail page and API record) | https://nvd.nist.gov/vuln/detail/CVE-2014-3704 ; `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2014-3704` | 2026-11-12 | Confirmed |
| 39 | Drupal, PSA-2014-003, 29 Oct 2014 | https://www.drupal.org/PSA-2014-003 | 2026-11-12 | Confirmed |
| 40 | US-CERT (CISA archive), TA14-317A, Apple iOS "Masque Attack" Technique, 13 Nov 2014 | https://www.cisa.gov/news-events/alerts/2014/11/13/apple-ios-masque-attack-technique | 2026-11-12 | Confirmed |
| 41 | US-CERT (CISA archive), Misfortune Cookie Broadband Router Vulnerability, 20 Dec 2014 | https://www.cisa.gov/news-events/alerts/2014/12/20/misfortune-cookie-broadband-router-vulnerability | 2026-11-12 | Confirmed |
| 42 | FBI, Five Chinese Military Hackers Charged with Cyber Espionage Against U.S., 19 May 2014 | https://www.fbi.gov/news/stories/five-chinese-military-hackers-charged-with-cyber-espionage-against-us | 2026-11-12 | Confirmed (as charged) |
| 43 | FBI, wanted notice, Wang Dong | https://www.fbi.gov/wanted/cyber/wang-dong | 2026-11-12 | Confirmed (as charged) |
| 44 | CrowdStrike, Hat-tribution to PLA Unit 61486, 9 Jun 2014 | https://www.crowdstrike.com/en-us/blog/hat-tribution-pla-unit-61486/ | 2026-11-12 | Confirmed (the vendor's findings) |
| 45 | CrowdStrike Intelligence Report, Putter Panda (PDF, hosted by Vox Media) | http://cdn0.vox-cdn.com/assets/4589853/crowdstrike-intelligence-report-putter-panda.original.pdf | 2026-11-12 | Confirmed (the vendor's findings) |
| 46 | Cisco Talos, Threat Spotlight: Group 72, 14 Oct 2014 | https://blogs.cisco.com/security/talos/threat-spotlight-group-72 | 2026-11-12 | Confirmed (the vendor's findings) |
| 47 | MITRE ATT&CK, G0001 Axiom | https://attack.mitre.org/groups/G0001/ | 2026-11-12 | Confirmed |
| 48 | MITRE ATT&CK, G0022 APT3 | https://attack.mitre.org/groups/G0022/ | 2026-11-12 | Reported (for the 2014 exploit and the MSS attribution, which rest on reports not opened) |
| 49 | Community Health Systems, Form 8-K, 18 Aug 2014 | `https://www.sec.gov/Archives/edgar/data/1108109/000119312514312504/d776541d8k.htm` | 2026-11-12 | Confirmed (the filing); Reported (the company's attribution) |
| 50 | ICS-CERT (CISA archive), ICS-ALERT-14-176-02A, ICS Focused Malware (Update A) | https://www.cisa.gov/news-events/ics-alerts/ics-alert-14-176-02a | 2026-11-12 | Confirmed |
| 51 | ICS-CERT (CISA archive), ICSA-14-178-01, ICS Focused Malware | https://www.cisa.gov/news-events/ics-advisories/icsa-14-178-01 | 2026-11-12 | Confirmed |
| 52 | Symantec (Broadcom), Dragonfly: Cyberespionage Attacks Against Energy Suppliers, v1.21, 7 Jul 2014 | https://docs.broadcom.com/doc/dragonfly_threat_against_western_energy_suppliers | 2026-11-12 | Confirmed (the vendor's findings) |
| 53 | MITRE ATT&CK, S0093 Backdoor.Oldrea | https://attack.mitre.org/software/S0093/ | 2026-11-12; 2026-11-13 | Confirmed |
| 54 | ICS-CERT (CISA archive), ICS-ALERT-14-281-01E, Ongoing Sophisticated Malware Campaign Compromising ICS (Update E) | https://www.cisa.gov/news-events/ics-alerts/ics-alert-14-281-01e | 2026-11-12 | Confirmed |
| 55 | F-Secure, BlackEnergy and Quedagh: The convergence of crimeware and APT attacks, 2014 | https://blog-assets.f-secure.com/wp-content/uploads/2019/10/15163408/BlackEnergy_Quedagh.pdf | 2026-11-12 | Confirmed (the vendor's findings) |
| 56 | MITRE ATT&CK, S0089 BlackEnergy | https://attack.mitre.org/software/S0089/ | 2026-11-12 | Confirmed |
| 57 | Kaspersky (Securelist), The Epic Turla Operation, 7 Aug 2014 | https://securelist.com/the-epic-turla-operation/65545/ | 2026-11-12 | Confirmed (the vendor's findings) |
| 58 | MITRE ATT&CK, G0007 APT28 | https://attack.mitre.org/groups/G0007/ | 2026-11-12 | Reported (the 2018 indictment was not opened) |
| 59 | Kaspersky (Securelist), The Careto/Mask APT: Frequently Asked Questions, 10 Feb 2014 | https://securelist.com/the-caretomask-apt-frequently-asked-questions/58254/ | 2026-11-12 | Confirmed (the vendor's findings) |
| 60 | Kaspersky (Securelist), El Machete, 20 Aug 2014 | https://securelist.com/el-machete/66108/ | 2026-11-12 | Confirmed (the vendor's findings) |
| 61 | Kaspersky (Securelist), The Darkhotel APT, 10 Nov 2014 | https://securelist.com/the-darkhotel-apt/66779/ | 2026-11-12 | Confirmed (the vendor's findings) |
| 62 | Kaspersky, The Darkhotel APT report (PDF) | https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08070903/darkhotel_kl_07.11.pdf | 2026-11-12 | Confirmed (the vendor's findings) |
| 63 | Kaspersky (Securelist), Regin: nation-state ownage of GSM networks, 24 Nov 2014 | https://securelist.com/regin-nation-state-ownage-of-gsm-networks/67741/ | 2026-11-12 | Confirmed (the vendor's findings) |
| 64 | US-CERT (CISA archive), TA14-329A, Regin Malware, 25 Nov 2014 | https://www.cisa.gov/news-events/alerts/2014/11/25/regin-malware | 2026-11-12 | Confirmed |
| 65 | MITRE ATT&CK, S0019 Regin | https://attack.mitre.org/software/S0019/ | 2026-11-12 | Confirmed |
| 66 | CrowdStrike, Cat Scratch Fever: CrowdStrike Tracks Newly Reported Iranian Actor as FLYING KITTEN, 13 May 2014 | https://www.crowdstrike.com/en-us/blog/cat-scratch-fever-crowdstrike-tracks-newly-reported-iranian-actor-flying-kitten/ | 2026-11-12 | Confirmed (the vendor's assessment) |
| 67 | eWeek, Newscaster Threat Uses Social Media for Intelligence Gathering, 28 May 2014 | https://www.eweek.com/security/newscaster-threat-uses-social-media-for-intelligence-gathering | 2026-11-12 | Reported |
| 68 | MITRE ATT&CK, G0003 Cleaver | https://attack.mitre.org/groups/G0003/ | 2026-11-12 | Reported (the Cylance report was not opened) |
| 69 | MITRE ATT&CK, G0094 Kimsuky | https://attack.mitre.org/groups/G0094/ | 2026-11-12 | Reported (for the KHNP assessment) |
| 70 | FBI, Update on Sony Investigation, 19 Dec 2014 | https://www.fbi.gov/news/press-releases/update-on-sony-investigation | 2026-11-12 | Confirmed |
| 71 | US-CERT (CISA archive), TA14-353A, Targeted Destructive Malware, 19 Dec 2014 | https://www.cisa.gov/news-events/alerts/2014/12/19/targeted-destructive-malware | 2026-11-12 | Confirmed |
| 72 | MITRE ATT&CK, G0032 Lazarus Group (and the library's group profile) | https://attack.mitre.org/groups/G0032/ | 2026-11-12 | Confirmed |
| 73 | eBay Inc., eBay Inc. To Ask eBay Users To Change Passwords, 21 May 2014 | https://www.ebayinc.com/stories/news/ebay-inc-ask-ebay-users-change-passwords/ | 2026-11-12 | Confirmed (the company's account) |
| 74 | eBay Inc., press release filed as Form 8-K exhibit 99.1, 22 May 2014 | `https://www.sec.gov/Archives/edgar/data/1065088/000106508814000097/exhibit991-521pressrelease.htm` | 2026-11-12 | Confirmed (the company's account) |
| 75 | Apple Newsroom, Apple Media Advisory, 2 Sep 2014 | https://www.apple.com/newsroom/2014/09/02Apple-Media-Advisory/ | 2026-11-12 | Confirmed (the company's account) |
| 76 | JPMorgan Chase & Co., Form 8-K, 2 Oct 2014 | `https://www.sec.gov/Archives/edgar/data/19617/000119312514362173/d799478d8k.htm` | 2026-11-12 | Confirmed (the company's account) |
| 77 | The Home Depot, Form 8-K, 8 Sep 2014 | `https://www.sec.gov/Archives/edgar/data/354950/000035495014000034/hd_8-kx982014.htm` | 2026-11-12 | Confirmed (the company's account) |
| 78 | The Home Depot, Form 8-K, 18 Sep 2014 | `https://www.sec.gov/Archives/edgar/data/354950/000035495014000036/hd_8kx09182014.htm` | 2026-11-12 | Confirmed (the company's account) |
| 79 | The Home Depot, Form 8-K, 6 Nov 2014 | `https://www.sec.gov/Archives/edgar/data/354950/000035495014000042/hd_8kx110614.htm` | 2026-11-12 | Confirmed (the company's account) |
| 80 | Sears Holdings, Form 8-K, 10 Oct 2014 | `https://www.sec.gov/Archives/edgar/data/1310067/000119312514369356/d803829d8k.htm` | 2026-11-12 | Confirmed (the company's account) |
| 81 | SUPERVALU, press release filed as Form 8-K exhibit 99, 14 Aug 2014 | `https://www.sec.gov/Archives/edgar/data/95521/000110465914061193/a14-19156_1ex99d1.htm` | 2026-11-12 | Confirmed (the company's account) |
| 82 | Neiman Marcus Group, Form 10-Q, filed 12 Mar 2014 | `https://www.sec.gov/Archives/edgar/data/1358651/000135865114000003/a2014020110q.htm` | 2026-11-12 | Confirmed (the company's account) |
| 83 | Michaels Stores, Form 10-K, filed 29 Apr 2014 | `https://www.sec.gov/Archives/edgar/data/740670/000110465914032010/a14-2849_110k.htm` | 2026-11-12 | Confirmed (the company's account) |
| 84 | Staples, Form 10-K for fiscal 2014, filed 6 Mar 2015 | `https://www.sec.gov/Archives/edgar/data/791519/000079151915000004/spls10-k01312015.htm` | 2026-11-12 | Confirmed (the company's account) |
| 85 | US-CERT (CISA archive), TA14-212A, Backoff Point-of-Sale Malware, 31 Jul 2014 | https://www.cisa.gov/news-events/alerts/2014/07/31/backoff-point-sale-malware | 2026-11-12 | Confirmed |
| 86 | Yahoo, Form 8-K exhibit 99.1, 22 Sep 2016 | `https://www.sec.gov/Archives/edgar/data/1011006/000119312516717056/d260014dex991.htm` | 2026-11-12 | Confirmed (the company's account); Reported (its state-sponsor belief) |
| 87 | FBI, International Blackshades Malware Takedown, 19 May 2014 | https://www.fbi.gov/news/stories/international-blackshades-malware-takedown-1 | 2026-11-12 | Confirmed (as charged) |
| 88 | FBI, GameOver Zeus Botnet Disrupted, 2 Jun 2014 | https://www.fbi.gov/news/stories/gameover-zeus-botnet-disrupted | 2026-11-12 | Confirmed (as charged) |
| 89 | FBI, wanted notice, Evgeniy Mikhailovich Bogachev | https://www.fbi.gov/wanted/cyber/evgeniy-mikhailovich-bogachev | 2026-11-12 | Confirmed (as charged) |
| 90 | US-CERT (CISA archive), TA14-150A, GameOver Zeus P2P Malware, 2 Jun 2014 | https://www.cisa.gov/news-events/alerts/2014/06/02/gameover-zeus-p2p-malware | 2026-11-12 | Confirmed |
| 91 | US-CERT (CISA archive), TA14-295A, Crypto Ransomware, 22 Oct 2014 | https://www.cisa.gov/news-events/alerts/2014/10/22/crypto-ransomware | 2026-11-12 | Confirmed |
| 92 | Microsoft On the Issues, Microsoft takes on global cybercrime epidemic in tenth malware disruption, 30 Jun 2014 | https://blogs.microsoft.com/blog/2014/06/30/microsoft-takes-on-global-cybercrime-epidemic-in-tenth-malware-disruption/ | 2026-11-12 | Confirmed (the company's account) |
| 93 | FBI New York, Operator of Silk Road 2.0 Website Charged in Manhattan Federal Court, 6 Nov 2014 | https://www.fbi.gov/contact-us/field-offices/newyork/news/press-releases/operator-of-silk-road-2.0-website-charged-in-manhattan-federal-court | 2026-11-12 | Confirmed (as charged) |
| 94 | BSI, Die Lage der IT-Sicherheit in Deutschland 2014 (PDF) | https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/Lageberichte/Lagebericht2014.pdf?__blob=publicationFile | 2026-11-12 | Confirmed |
| 95 | ICS-CERT, ICS-CERT Monitor, September 2014 to February 2015 (PDF) | https://www.cisa.gov/sites/default/files/Monitors/ICS-CERT_Monitor_Sep2014-Feb2015.pdf | 2026-11-12 | Confirmed |
| 96 | NIST, NIST Releases Cybersecurity Framework Version 1.0, 12 Feb 2014 | https://www.nist.gov/news-events/news/2014/02/nist-releases-cybersecurity-framework-version-10 | 2026-11-12 | Confirmed |
| 97 | The White House (archive), Presidential Policy Directive 28, Signals Intelligence Activities, 17 Jan 2014 | https://obamawhitehouse.archives.gov/the-press-office/2014/01/17/presidential-policy-directive-signals-intelligence-activities | 2026-11-12 | Confirmed |
| 98 | Court of Justice of the European Union, press release 54/14, Digital Rights Ireland (C-293/12 and C-594/12), 8 Apr 2014 | https://curia.europa.eu/jcms/upload/docs/application/pdf/2014-04/cp140054en.pdf | 2026-11-12 | Confirmed |
| 99 | Court of Justice of the European Union, press release 70/14, Google Spain (C-131/12), 13 May 2014 | https://curia.europa.eu/jcms/upload/docs/application/pdf/2014-05/cp140070en.pdf | 2026-11-12 | Confirmed |
| 100 | Legal Information Institute (Cornell), Riley v. California, 573 U.S. 373 (2014) | https://www.law.cornell.edu/supremecourt/text/13-132 | 2026-11-12 | Confirmed |
| 101 | SEC Office of Compliance Inspections and Examinations, Cybersecurity Initiative risk alert and appendix, 15 Apr 2014 | `https://www.sec.gov/ocie/announcement/Cybersecurity-Risk-Alert--Appendix---4.15.14.pdf` | 2026-11-12 | Confirmed |
| 102 | SEC, Commissioner Luis A. Aguilar, Boards of Directors, Corporate Governance and Cyber-Risks: Sharpening the Focus, 10 Jun 2014 | `https://www.sec.gov/newsroom/speeches-statements/2014-spch061014laa` | 2026-11-12 | Confirmed |
| 103 | Federal Register, Executive Order 13681, Improving the Security of Consumer Financial Transactions, 17 Oct 2014 | https://www.federalregister.gov/documents/2014/10/23/2014-25439/improving-the-security-of-consumer-financial-transactions | 2026-11-12 | Confirmed |
| 104 | GovInfo, Public Law 113-283, Federal Information Security Modernization Act of 2014 | https://www.govinfo.gov/content/pkg/PLAW-113publ283/html/PLAW-113publ283.htm | 2026-11-12 | Confirmed |
| 105 | GovInfo, Public Law 113-274, Cybersecurity Enhancement Act of 2014 | https://www.govinfo.gov/content/pkg/PLAW-113publ274/html/PLAW-113publ274.htm | 2026-11-12 | Confirmed |
| 106 | GovInfo, Public Law 113-282, National Cybersecurity Protection Act of 2014 | https://www.govinfo.gov/content/pkg/PLAW-113publ282/html/PLAW-113publ282.htm | 2026-11-12 | Confirmed |
| 107 | NATO, Wales Summit Declaration, 5 Sep 2014 | https://www.nato.int/cps/en/natohq/official_texts_112964.htm | 2026-11-12 | Confirmed |
| 108 | GOV.UK, Cyber Essentials scheme: overview | https://www.gov.uk/government/publications/cyber-essentials-scheme-overview | 2026-11-12 | Confirmed |
| 109 | IETF (RFC Editor), RFC 7258, Pervasive Monitoring Is an Attack, May 2014 | https://www.rfc-editor.org/rfc/rfc7258.txt | 2026-11-12 | Confirmed |
| 110 | Google Search Central Blog, HTTPS as a ranking signal, 7 Aug 2014 | https://developers.google.com/search/blog/2014/08/https-as-ranking-signal | 2026-11-12 | Confirmed |
| 111 | Electronic Frontier Foundation, Launching in 2015: A Certificate Authority to Encrypt the Entire Web, 18 Nov 2014 | https://www.eff.org/deeplinks/2014/11/certificate-authority-encrypt-entire-web | 2026-11-12 | Confirmed |
| 112 | Google Project Zero, Announcing Project Zero, 15 Jul 2014 | https://projectzero.google/2014/07/announcing-project-zero.html | 2026-11-12 | Confirmed |
| 113 | LibreSSL project home page | https://www.libressl.org/ | 2026-11-12 | Confirmed |
| 114 | CVE (archived page), CVE-ID Syntax Change | https://www.cve.org/Resources/Media/Archives/OldWebsite/cve/identifiers/syntaxchange.html | 2026-11-12 | Confirmed |
| 115 | MITRE CWE, News Archive 2014 | https://cwe.mitre.org/news/archives/news2014.html | 2026-11-12 | Confirmed |
| 116 | MITRE CAPEC, News Archive 2014 | https://capec.mitre.org/news/archives/news2014.html | 2026-11-12 | Confirmed |
| 117 | MITRE, ATT&CK: Design and Philosophy, March 2020 (PDF) | https://attack.mitre.org/docs/ATTACK_Design_and_Philosophy_March_2020.pdf | 2026-11-12 | Confirmed |
| 118 | MITRE ATT&CK, T1212 Exploitation for Credential Access | https://attack.mitre.org/techniques/T1212/ | 2026-11-12 | Confirmed |
| 119 | MITRE ATT&CK, T1557 Adversary-in-the-Middle | https://attack.mitre.org/techniques/T1557/ | 2026-11-12 | Confirmed |
| 120 | TeamStarWolf Intelligence Hub, history shards for 2014 (`history/cisa-alerts/2014.jsonl`, `history/cisa-ics-csaf/2014.jsonl`) | https://github.com/TeamStarWolf/intelligence-hub/tree/main/history/cisa-ics-csaf | 2026-11-12 | Demonstrated |
| 121 | TeamStarWolf library, ATT&CK and ICS data (`data/attack/`, `data/attack/ics/`, including `groups.jsonl`, `group_profiles.jsonl`, `software.jsonl`, `software_profiles.jsonl`, `group_to_technique.jsonl`, `software_to_technique.jsonl`, `campaigns.jsonl` and `technique_profiles.jsonl`) | https://github.com/TeamStarWolf/TeamStarWolf/tree/main/data/attack | 2026-11-12; 2026-11-13 | Confirmed (what ATT&CK records); Demonstrated (this study's checks) |
| 122 | TeamStarWolf library, weakness data (`data/weaknesses/capec.jsonl`, `data/weaknesses/cwe.jsonl`) | https://github.com/TeamStarWolf/TeamStarWolf/tree/main/data/weaknesses | 2026-11-12; 2026-11-13 | Demonstrated |
| 123 | TeamStarWolf library, D3FEND data (`data/attack/d3fend_countermeasures.jsonl`, `data/attack/technique_to_d3fend.jsonl`) | https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/data/attack/d3fend_countermeasures.jsonl | 2026-11-12; 2026-11-13 | Demonstrated |
| 124 | TeamStarWolf library, `mitre/` page tree (technique, group, software, CAPEC, D3FEND and mitigation pages) | https://github.com/TeamStarWolf/TeamStarWolf/tree/main/mitre | 2026-11-12; 2026-11-13 | Demonstrated |
| 125 | TeamStarWolf library, chronicle Navigator layers (`navigator/library-layers/chronicle-2016.json` and `navigator/case-studies/chronicle-2016-ics.json` and the later years) | https://github.com/TeamStarWolf/TeamStarWolf/tree/main/navigator/library-layers | 2026-11-13 | Demonstrated |
| 126 | TeamStarWolf library, case studies on main (home studies named in the text: `ECOMMERCE_THREATS.md`, `HACKER_AND_THE_STATE_CASES.md`, `SANDWORM_OPERATIONS.md`, `THREAT_ACTORS_IRAN.md`, `CHRONICLE_2016.md`, `NSA_CIA_TOOL_LEAKS.md`, `CYBERCRIME_FOUR_BOOKS.md` and the others linked above) | https://github.com/TeamStarWolf/TeamStarWolf/tree/main/case-studies | 2026-11-12; 2026-11-13 | Confirmed (for the fact that a study is the home and for the facts it carries from its own sources, at the grade it gives them) |
| 127 | NVD, CVE-2014-1776 (API record) | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2014-1776` | 2026-11-12; 2026-11-13 | Confirmed |

*© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.*

*© The MITRE Corporation. Includes material from the Common Weakness Enumeration (CWE™), used under the CWE Terms of Use. https://cwe.mitre.org/*

*© The MITRE Corporation. Includes material from the Common Attack Pattern Enumeration and Classification (CAPEC™), used under the CAPEC Terms of Use. https://capec.mitre.org/*

*© The MITRE Corporation. Includes material from MITRE D3FEND™, used under the D3FEND Terms of Use. https://d3fend.mitre.org/*

*The terms for every MITRE dataset used here are recorded in [THIRD_PARTY_NOTICES.md](/THIRD_PARTY_NOTICES.md).*

## Related references

- [Notable Incidents](/NOTABLE_INCIDENTS.md), [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [CVE Reference](/CVE_REFERENCE.md)
- [Threat Intelligence](/THREAT_INTELLIGENCE_REFERENCE.md), [Cryptography](/CRYPTOGRAPHY_REFERENCE.md), [Web Application Security](/WEB_APPLICATION_SECURITY_REFERENCE.md), [Email Security](/EMAIL_SECURITY_REFERENCE.md), [Identity and Access Management](/IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md), [Supply Chain Security](/SUPPLY_CHAIN_SECURITY_REFERENCE.md), [Ransomware Defense](/RANSOMWARE_DEFENSE_REFERENCE.md), [CWE Reference](/CWE_REFERENCE.md), [CAPEC Reference](/CAPEC_REFERENCE.md), [D3FEND Reference](/D3FEND_REFERENCE.md), [GRC and Compliance](/GRC_COMPLIANCE_REFERENCE.md), [Vulnerability Management](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [Incident Response](/INCIDENT_RESPONSE_REFERENCE.md), [ICS/OT Security](/ICS_OT_SECURITY_REFERENCE.md)
- Home studies: [E-Commerce Threats](/case-studies/ECOMMERCE_THREATS.md); [China-attributed threat actors](/case-studies/THREAT_ACTORS_CHINA.md); [APT41](/case-studies/APT41_PUBLIC_RECORD.md); [The Hacker and the State](/case-studies/HACKER_AND_THE_STATE_CASES.md); [North Korea-attributed threat actors](/case-studies/THREAT_ACTORS_NORTH_KOREA.md); [Russia-attributed threat actors](/case-studies/THREAT_ACTORS_RUSSIA.md); [Sandworm Operations](/case-studies/SANDWORM_OPERATIONS.md); [Iran-attributed threat actors](/case-studies/THREAT_ACTORS_IRAN.md); [Other states' threat actors](/case-studies/THREAT_ACTORS_OTHER_STATES.md); [United States-attributed threat actors](/case-studies/THREAT_ACTORS_UNITED_STATES.md); [NSA and CIA tool leaks](/case-studies/NSA_CIA_TOOL_LEAKS.md); [The Zero-Day Market](/case-studies/ZERO_DAY_MARKET_EVENTS.md); [Cybercrime and Hacktivism in Four Books](/case-studies/CYBERCRIME_FOUR_BOOKS.md); [Ransomware ecosystem](/case-studies/RANSOMWARE_ECOSYSTEM.md); [ICS attacks and advisories](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md); [Stuxnet](/case-studies/STUXNET.md); [Log4Shell](/case-studies/LOG4SHELL.md); [SolarWinds SUNBURST](/case-studies/SOLARWINDS_SUNBURST.md); [npm supply-chain attacks](/case-studies/NPM_SUPPLY_CHAIN_ATTACKS.md); [Hugging Face supply chain](/case-studies/HUGGING_FACE_SUPPLY_CHAIN.md)
- Series: [1993](/case-studies/CHRONICLE_1993.md), [1994](/case-studies/CHRONICLE_1994.md), [1995](/case-studies/CHRONICLE_1995.md), [1996](/case-studies/CHRONICLE_1996.md), [1997](/case-studies/CHRONICLE_1997.md), [1998](/case-studies/CHRONICLE_1998.md), [1999](/case-studies/CHRONICLE_1999.md), [2000](/case-studies/CHRONICLE_2000.md), [2001](/case-studies/CHRONICLE_2001.md), [2002](/case-studies/CHRONICLE_2002.md), [2003](/case-studies/CHRONICLE_2003.md), [2004](/case-studies/CHRONICLE_2004.md), [2005](/case-studies/CHRONICLE_2005.md), [2006](/case-studies/CHRONICLE_2006.md), [2007](/case-studies/CHRONICLE_2007.md), [2010](/case-studies/CHRONICLE_2010.md), [2011](/case-studies/CHRONICLE_2011.md), [2012](/case-studies/CHRONICLE_2012.md), [2016](/case-studies/CHRONICLE_2016.md), [2017](/case-studies/CHRONICLE_2017.md), [2018](/case-studies/CHRONICLE_2018.md), [2019](/case-studies/CHRONICLE_2019.md), [2020](/case-studies/CHRONICLE_2020.md), [2021](/case-studies/CHRONICLE_2021.md), [2022](/case-studies/CHRONICLE_2022.md), [2023](/case-studies/CHRONICLE_2023.md), [2024](/case-studies/CHRONICLE_2024.md), [2025](/case-studies/CHRONICLE_2025.md), [2026](/case-studies/CHRONICLE_2026.md)
- Techniques: [T1190 Exploit Public-Facing Application](/mitre/techniques/T1190.md), [T1203 Exploitation for Client Execution](/mitre/techniques/T1203.md), [T1212 Exploitation for Credential Access](/mitre/techniques/T1212.md), [T1558 Steal or Forge Kerberos Tickets](/mitre/techniques/T1558.md), [T1552.006 Group Policy Preferences](/mitre/techniques/T1552-006.md), [T1557 Adversary-in-the-Middle](/mitre/techniques/T1557.md), [T1195.002 Compromise Software Supply Chain](/mitre/techniques/T1195-002.md), [T1199 Trusted Relationship](/mitre/techniques/T1199.md), [T1133 External Remote Services](/mitre/techniques/T1133.md), [T1566.001 Spearphishing Attachment](/mitre/techniques/T1566-001.md), [T1189 Drive-by Compromise](/mitre/techniques/T1189.md), [T1561.002 Disk Structure Wipe](/mitre/techniques/T1561-002.md), [T1485 Data Destruction](/mitre/techniques/T1485.md), [T1486 Data Encrypted for Impact](/mitre/techniques/T1486.md), [T1498.002 Reflection Amplification](/mitre/techniques/T1498-002.md); the full list is in the Part 12 table
- CAPEC: [CAPEC-540](/mitre/capec/CAPEC-540.md), [CAPEC-88](/mitre/capec/CAPEC-88.md), [CAPEC-620](/mitre/capec/CAPEC-620.md), [CAPEC-66](/mitre/capec/CAPEC-66.md), [CAPEC-652](/mitre/capec/CAPEC-652.md), [CAPEC-639](/mitre/capec/CAPEC-639.md), [CAPEC-565](/mitre/capec/CAPEC-565.md), [CAPEC-112](/mitre/capec/CAPEC-112.md), [CAPEC-561](/mitre/capec/CAPEC-561.md), [CAPEC-560](/mitre/capec/CAPEC-560.md), [CAPEC-568](/mitre/capec/CAPEC-568.md), [CAPEC-98](/mitre/capec/CAPEC-98.md), [CAPEC-163](/mitre/capec/CAPEC-163.md), [CAPEC-94](/mitre/capec/CAPEC-94.md), [CAPEC-186](/mitre/capec/CAPEC-186.md), [CAPEC-552](/mitre/capec/CAPEC-552.md), [CAPEC-68](/mitre/capec/CAPEC-68.md), [CAPEC-490](/mitre/capec/CAPEC-490.md)
- Groups and software: APT1 [G0006](/mitre/groups/G0006.md); Putter Panda [G0024](/mitre/groups/G0024.md); Axiom [G0001](/mitre/groups/G0001.md); APT3 [G0022](/mitre/groups/G0022.md); Threat Group-3390 [G0027](/mitre/groups/G0027.md); Dragonfly [G0035](/mitre/groups/G0035.md); Sandworm Team [G0034](/mitre/groups/G0034.md); Turla [G0010](/mitre/groups/G0010.md); APT28 [G0007](/mitre/groups/G0007.md); Machete [G0095](/mitre/groups/G0095.md); Darkhotel [G0012](/mitre/groups/G0012.md); Ajax Security Team [G0130](/mitre/groups/G0130.md); Magic Hound [G0059](/mitre/groups/G0059.md); Cleaver [G0003](/mitre/groups/G0003.md); Kimsuky [G0094](/mitre/groups/G0094.md); Lazarus Group [G0032](/mitre/groups/G0032.md); Carbanak [G0008](/mitre/groups/G0008.md); Backdoor.Oldrea [S0093](/mitre/software/S0093.md); Trojan.Karagany [S0094](/mitre/software/S0094.md); BlackEnergy [S0089](/mitre/software/S0089.md); Epic [S0091](/mitre/software/S0091.md); Uroburos [S0022](/mitre/software/S0022.md); Regin [S0019](/mitre/software/S0019.md); Machete [S0409](/mitre/software/S0409.md); P2P ZeuS [S0016](/mitre/software/S0016.md); njRAT [S0385](/mitre/software/S0385.md); Emotet [S0367](/mitre/software/S0367.md); Dridex [S0384](/mitre/software/S0384.md); Dyre [S0024](/mitre/software/S0024.md); Carbanak [S0030](/mitre/software/S0030.md); Mimikatz [S0002](/mitre/software/S0002.md)
- [Navigator layers](/navigator/index.md), including this study's layers, [chronicle-2014.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/chronicle-2014.json) and [chronicle-2014-ics.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/case-studies/chronicle-2014-ics.json)
