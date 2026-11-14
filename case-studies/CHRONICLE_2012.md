# The Year 2012 in Intrusions: A Dated Record

*A TeamStarWolf case study. Published 13 November 2026; every source checked as of that date.*

[All case studies](/case-studies/README.md) · Related: [Notable Incidents](/NOTABLE_INCIDENTS.md), [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [CVE Reference](/CVE_REFERENCE.md), [Certificate Trust Incident Response](/CERTIFICATE_TRUST_INCIDENT_RESPONSE_REFERENCE.md), [Cryptography](/CRYPTOGRAPHY_REFERENCE.md), [Browser Security](/BROWSER_SECURITY_REFERENCE.md), [GRC and Compliance](/GRC_COMPLIANCE_REFERENCE.md), [Incident Response](/INCIDENT_RESPONSE_REFERENCE.md), [Vulnerability Management](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [ICS/OT Security](/ICS_OT_SECURITY_REFERENCE.md) · Home studies for events summarized here: [Stuxnet](/case-studies/STUXNET.md) (Flame, Gauss, the Microsoft certificate response and the Flame to Stuxnet link), [United States-attributed threat actors](/case-studies/THREAT_ACTORS_UNITED_STATES.md) (Flame), [Iran-attributed threat actors](/case-studies/THREAT_ACTORS_IRAN.md) (Shamoon and the 2011 to 2013 financial-sector DDoS), [The Hacker and the State](/case-studies/HACKER_AND_THE_STATE_CASES.md) (Shamoon and OPM's first known access), [China-attributed threat actors](/case-studies/THREAT_ACTORS_CHINA.md) (APT1 and Elderwood), [The Zero-Day Market](/case-studies/ZERO_DAY_MARKET_EVENTS.md) (Elderwood and Aurora), [Russia-attributed threat actors](/case-studies/THREAT_ACTORS_RUSSIA.md) (Epic Turla), [Four Books on Cybercrime](/case-studies/CYBERCRIME_FOUR_BOOKS.md) (LulzSec, AntiSec and Stratfor), [Cloud Security Incidents](/case-studies/CLOUD_SECURITY_INCIDENTS.md) (Dropbox), [E-Commerce Threats](/case-studies/ECOMMERCE_THREATS.md) (Wyndham), [APT41](/case-studies/APT41_PUBLIC_RECORD.md) (APT41 from 2012) · Series: [The Year 2010 in Intrusions](/case-studies/CHRONICLE_2010.md), [The Year 2016 in Intrusions](/case-studies/CHRONICLE_2016.md) and the other years in the [case studies index](/case-studies/README.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Threat intelligence analysts, security historians, vulnerability management, PKI, payment-card and finance teams and anyone who wants the history behind current threats

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Beginner to intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 74 min (17,080 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want a dated record of the intrusions of 2012, you need Flame, Gauss, the Microsoft certificate response, Wiper and Shamoon side by side with the bank DDoS, Elderwood, APT1 and the year's exploited Java, Internet Explorer, Office and Flash flaws, the breaches that became filings, the takedowns that went to court, the standards that followed, or you want the defender lessons that still apply

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [Part 4: the state and espionage record](#part-4-the-state-and-espionage-record), [Part 7: the vulnerability record](#part-7-the-vulnerability-record)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Notable Incidents](/NOTABLE_INCIDENTS.md), [Stuxnet: The Case Study](/case-studies/STUXNET.md), [Iran-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_IRAN.md), [The Year 2010 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2010.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive summary

The year's espionage toolkit came to light while researchers were looking for something else. The International Telecommunication Union asked Kaspersky to find malware that had wiped data on systems in Iran, most of it between 21 and 30 April, and that search found Flame, which Kaspersky published on 28 May (Confirmed [19][20]). Kaspersky saw Flame in use from at least August 2010, mostly against targets in Iran, Lebanon, Syria and Israel, and judged it about 20 times larger than Stuxnet; Hungary's CrySyS Lab published its own report, calling the malware sKyWIper, three days later (Confirmed [20][21]). On 3 June Microsoft revoked trust in three of its own intermediate certificate authorities after active attacks used certificates derived from a Microsoft CA, and its security response blog explained that the attacker needed an MD5 collision to make a Terminal Server licensing certificate sign code (Confirmed [23][25][26]). The advisory itself does not name Flame (Confirmed [23]). In August Kaspersky described Gauss, built on the Flame platform, which steals online-banking credentials for Lebanese banks (Confirmed [36][37]). The home for all three is the [Stuxnet](/case-studies/STUXNET.md) study.

Destructive malware followed. Kaspersky's analysis of Shamoon on 16 August found a wiper that overwrites the master boot record through a raw-disk driver signed by EldoS Corporation, judged it "more likely" a copycat of the Wiper that hit Iran, not the original, and named no victim (Confirmed [39]). ATT&CK records Shamoon as first used in 2012 by an Iranian group known as the Cutting Sword of Justice (Confirmed that ATT&CK says so [40]; the attribution is Reported). The home study names the 2012 targets as Saudi Aramco and RasGas from Kaspersky's 2017 report (Confirmed that the home study carries it [115]). The home studies record Unit 42's later description of the target as a Saudi energy company with 30,000 or more systems damaged; no primary for that figure was opened (Reported [115]).

The financial sector took the year's largest denial-of-service campaign. PNC told the SEC that a series of apparently related denial-of-service attacks temporarily disrupted customers' online banking, and Capital One that DDoS attacks by sophisticated third parties disrupted consumer online banking at least once; neither named an attacker (Confirmed [52][53]). A 2016 indictment alleges that seven Iranian nationals working for ITSecTeam and Mersad, private companies acting for the Iranian Government including the IRGC, ran the campaign: sporadic attacks from about December 2011, near-weekly attacks from September 2012, up to about 140 Gbps, against at least 46 major financial institutions over at least 176 days (Confirmed as alleged [56][57]).

Espionage reporting widened. Symantec's "The Elderwood Project" of 6 September tied the 2009 Aurora attackers to four 2012 zero-days and a shift to watering-hole attacks (Confirmed [46][45]). Mandiant's APT1 report, published in February 2013, carries APT1's spearphishing of Mandiant's own staff on 18 April 2012 and attributes the Telvent Canada breach to APT1 (Confirmed as Mandiant's findings [58]). The 2014 indictment of five PLA officers alleges 2012 thefts of e-mail and credentials from United Steelworkers, ATI and SolarWorld timed to trade disputes (Confirmed as alleged [60]). Kaspersky's Madi report of July 2012, its Red October investigation begun in October 2012 (against a network active since about 2007) and its 2014 Epic Turla report (artifacts dated September 2012) add campaigns active in 2012 (Confirmed [34][63][64]; the Epic Turla start date is Inferred).

Clients were the front door. The flaws the record shows exploited in 2012 sit in Java, Internet Explorer, Office's common controls, XML Core Services and Flash, and CISA's Known Exploited Vulnerabilities catalog added most of them only from 2021 (Confirmed [14][30][38][41][47][55]; Inferred for the reading). Payment data and passwords were lost at scale: Global Payments said up to 1,500,000 card numbers may have been exported and booked a USD 84.4 million pre-tax charge, LinkedIn said about 6.5 million encrypted passwords were stolen and published, and Dropbox said passwords stolen from other websites opened accounts and an employee's account (Confirmed [9][10][11][28][35]). Courts and companies shut down Megaupload, seized Zeus-family command servers and put the Nitol botnet's 3322.org domain under Microsoft's control, and ran a two-year carding sting (Confirmed [1][12][13][32]). Standards moved toward rebuilding trust: HSTS, DANE, OAuth 2.0, FIPS 180-4, the SHA-3 selection, and Windows refusing RSA keys under 1024 bits (Confirmed [99][97][98][94][95][103]; Inferred for the reading).

This study records the year by date. It is built only from sources opened on 12 and 13 November 2026 and from checks of the library's data run on those days, and is checked as of 13 November 2026.

### Key facts at a glance

| Field | Value |
|---|---|
| Period | 1 January to 31 December 2012, plus the records that open, close or explain a 2012 event: the December 2011 Stratfor hack, Mandiant's APT1 report of February 2013, the 2014 PLA and 2016 Iran indictments, the 2014 Epic Turla report, the 2016 Dropbox credential set and KEV additions from 2021 to 2026 |
| Flame, Gauss and the certificate response | Wiper incidents in Iran (21 to 30 Apr); Flame published (28 May); CrySyS sKyWIper (31 May); Advisory 2718704 (3 Jun); MSRC collision post (6 Jun); Kaspersky's Flame to Stuxnet link (11 Jun); Advisory 2728973 (12 Jul); Gauss (9 Aug) (Confirmed [19][20][21][23][26][33][36][37]; Reported [27]) |
| Wipers | Wiper (Apr, no complete sample); Shamoon (Kaspersky, 16 Aug; ATT&CK S0140 first used 2012) (Confirmed [19][39][40]) |
| Financial-sector DDoS | Sporadic from about Dec 2011, near-weekly from Sep 2012, up to about 140 Gbps, 46 institutions, 176 days, as alleged; PNC and Capital One disclosures (Confirmed as alleged [57]; Confirmed [52][53]) |
| Espionage reports | APT1 phishes Mandiant (18 Apr); USW, ATI and SolarWorld thefts (Jan to Sep, as alleged); Madi (17 Jul); OPM first access (Jul); Elderwood (6 Sep); Telvent (10 Sep); Red October investigation (Oct) (Confirmed [58][60][34][81][46][63]; Reported [84]) |
| Breaches | Global Payments (early Mar; 8-K 30 Mar; charge 26 Jul); LinkedIn (Jun); Dropbox (31 Jul); Barnes & Noble PIN pads (24 Oct) (Confirmed [8][11][28][35][54]) |
| Takedowns and arrests | Megaupload (19 Jan); LulzSec and AntiSec charges (6 Mar); Zeus-family servers seized (23 Mar); Card Shop (26 Jun); DNSChanger servers off (9 Jul); Nitol (10 Sep) (Confirmed [1][6][12][32][3][13]) |
| Exploited in 2012 per the vendor, US-CERT or NVD | CVE-2012-0158 (Office common controls); CVE-2012-1889 (MSXML); CVE-2012-1535 (Flash); CVE-2012-4681 (Java 7); CVE-2012-4969 (IE); CVE-2012-0507 (Java, per Dr.Web) (Confirmed [14][30][38][41][49]; Reported [16]) |
| KEV tail | 22 CVE-2012 entries in catalog 2026.11.10, added from 3 November 2021 to 13 April 2026; five marked with known ransomware use (Confirmed [55]) |
| Microsoft's year | MS12-001 (10 Jan) to MS12-083 (11 Dec): 83 bulletins by numbering (Confirmed [72]; count Inferred) |
| CVE volume | 5,351 CVE records published in 2012 by NVD publication date (Confirmed [108]) |
| Policy and standards | RFC 6520 (Feb); FIPS 180-4 (6 Mar); CISPA passes the House (26 Apr); RFC 6698 (Aug); SP 800-61 Rev. 2 (Aug); Cybersecurity Act cloture fails (2 Aug); 2661254 (14 Aug); SP 800-30 Rev. 1 (17 Sep); SHA-3 (2 Oct); RFC 6749 (Oct); RFC 6797 (Nov); WCIT-12 (3 to 14 Dec) (Confirmed [96][94][89][97][91][90][103][92][95][98][99][93]) |
| This study's MITRE binding | 36 ATT&CK Enterprise techniques in 41 technique-tactic entries: 22 listed by ATT&CK for Flame (S0143), Shamoon (S0140, the two 2012-sourced ids), Elderwood (G0066) or APT1 (G0006), 11 described by a primary and assigned here, and three inferred; two ATT&CK for ICS techniques listed for Flame; CWE ids from NVD and the CVE record; CAPEC and D3FEND pairings from the library's data; one Enterprise Navigator layer (Part 12) |

### Key findings

- **One investigation found two toolkits.** The ITU's request to find the wiper that hit Iran led Kaspersky to Flame and later to Gauss, and the wiper itself was never recovered as a complete sample (Confirmed [19][20][37]).
- **A vendor's own PKI became the attack surface.** Microsoft revoked three of its intermediate CAs after unauthorized certificates derived from them were used in active attacks; the MSRC blog says a collision attack made a licensing certificate valid for code signing (Confirmed [23][26]).
- **Wiper attacks became public in 2012, and their attribution stayed thin.** Kaspersky named no victim and no state for Wiper or Shamoon; ATT&CK's Iranian attribution names a group known as the Cutting Sword of Justice and gives no government finding (Confirmed [19][39][40]; Inferred for the reading).
- **The bank DDoS was public in 2012 and attributed in 2016.** Bank filings describe disruptions without naming an attacker, and the indictment naming Iranian contractors came four years later (Confirmed [52][53][56]).
- **Trade disputes timed the PLA thefts, as alleged.** The 2014 indictment places the USW theft the day after USW's public trade statements and the ATI access the day after a joint-venture board meeting (Confirmed as alleged [60]).
- **Watering holes joined spearphishing.** Elderwood used four 2012 zero-days, three of them within 30 days, and compromised sites its targets visited; US-CERT warned in September that compromised CMS sites were infecting visitors (Confirmed [46][50]).
- **Browser plug-ins carried the year's mass exploitation.** Flashback reached about 550,000 Macs through Java flaws by Dr.Web's count, Reveton arrived by drive-by download, and US-CERT advised disabling Java in browsers (Reported [16]; Confirmed [77][41]).
- **Payment processing was the costliest breach on the record.** Global Payments' USD 84.4 million pre-tax charge is the only booked loss figure in this study (Confirmed [11]; Inferred for the comparison).
- **Password reuse moved between companies.** Dropbox's 2012 account takeovers used passwords stolen from other websites, in the year LinkedIn's encrypted passwords were published (Confirmed [35][28]).
- **No 2012 event had an ATT&CK mapping at the time, and KEV came a decade later.** The Flame and Shamoon objects were created in 2017, and CVE-2012-4792 entered KEV in 2024 (Confirmed [22][40][55][73]; Inferred).

### Top recommendations

1. **Remove Java from browsers where it is not needed.** US-CERT advised disabling Java in web browsers for CVE-2012-4681, and three 2012 Java flaws are in KEV with known ransomware use (Confirmed [41][55]).
2. **Deploy the vendor's interim workaround while the fix is pending.** Microsoft offered a Fix it for CVE-2012-4969 on 19 September and the bulletin on 21 September; for CVE-2012-1889 a Fix it was available when US-CERT alerted on 22 June, 18 days before MS12-043 (Confirmed [47][48][30][31]).
3. **Keep an inventory of trusted CAs and code-signing certificates and a way to pull one fast.** Microsoft untrusted its own intermediates and further non-conforming CAs, and Adobe revoked a code-signing certificate used to sign malicious code (Confirmed [23][33][51]).
4. **Find the weak keys before Windows does.** Advisory 2661254 stopped trust in RSA keys under 1024 bits in chains built through CertGetCertificateChain, including private PKIs, and logging of blocked certificates is off by default (Confirmed [103]).
5. **Stop password reuse with a second factor.** Dropbox's takeovers used passwords from other sites, and Dropbox answered with two-factor authentication (Confirmed [35]).
6. **Agree DDoS capacity and escalation with your providers before you need them.** The bank campaign reached about 140 Gbps as alleged, and it disrupted online banking at PNC and Capital One (Confirmed as alleged [57]; Confirmed [52][53]).
7. **Keep backups where a wiper cannot reach them.** DHS and the FBI advised backups in a separate, secure location on 19 January, before the April Wiper incidents and Shamoon (Confirmed [86][19][39]).
8. **Inspect card-handling hardware and processing networks.** Barnes & Noble found tampered PIN pads, and Global Payments found card data exported from its processing system (Confirmed [54][9]).
9. **Patch public web stacks and recheck vendor fixes.** PHP said its first CGI fix did not cover every variation, and US-CERT reported increased exploitation of WordPress and Joomla (Confirmed [75][50]).
10. **Do not read KEV dates as event dates.** CVE-2012-0158 was exploited in limited targeted attacks in April 2012 and added to KEV in November 2021 (Confirmed [14][55]).

## Scope and method

This study covers intrusions, malware, wipers, denial of service, vulnerabilities, data breaches, crimeware and takedowns, hacktivism and prosecutions, state and espionage operations, industrial-control disclosures, regulation, standards and policy dated to 2012, plus the later records that open, close or explain a 2012 event. It follows the method of the [case studies collection](/case-studies/README.md): primary sources first, every claim graded, and numbers given as the source states them. Every external source was opened on 12 or 13 November 2026, as the Sources table shows, and the library data checks were run on the same days.

| Grade | Meaning in this study |
|---|---|
| Confirmed | The primary record was opened and states the fact: a vendor advisory, bulletin or blog, a company's own statement or SEC filing, a CERT/CC, US-CERT, ICS-CERT or CISA record, a CVE or NVD record, the KEV catalog, an FBI, US Attorney or court record, a government, parliamentary or EU record, a NIST, IETF, ITU or MITRE record, a researchers' or vendor's report stated as its own finding, a live ATT&CK page, or a library study, only for the fact that it is the home for an event |
| Reported | Only a secondary source supports the fact, or a source relays someone else's claim or makes an attribution or estimate that is its own assessment: Dr.Web's Flashback counts, Kaspersky's Flame to Stuxnet kinship and its "nation-state" label for Gauss, ATT&CK's Iranian attribution for Shamoon, Microsoft's experts' damage estimate for Zeus, KrebsOnSecurity's Telvent account and the Unit 42 figure carried by a home study. The source is named in the text |
| Demonstrated | A check this study ran itself and saw the result: id, name, tactic, CAPEC, D3FEND and page checks in the library's data files and `mitre/` tree |
| Inferred | The study's own reading, labelled where it appears. Every ATT&CK, CAPEC and D3FEND id bound to a 2012 event is Inferred as to the binding unless ATT&CK lists it for the object, and so is every CWE that neither NVD nor the CVE record lists |

Charges, complaints and indictments are allegations; where this study cites one, the record confirms that the charge was made, not that it was proven. Company statements are the company's own account, and vendor and researcher attributions are those authors' assessments, not government findings.

Limits a reader should know:

- **CVE existed; ATT&CK and KEV did not.** Every 2012 product flaw here carries a CVE id. No 2012 record carries a technique id; the Flame and Shamoon objects were created in 2017, and every technique id in Part 12 is assigned in hindsight from later ATT&CK records or by this study (Confirmed [22][40]; Inferred). KEV's 2012 entries were added from November 2021 to April 2026 (Confirmed [55]).
- **Some events have no ATT&CK object.** Gauss, Madi, Red October, the Wiper that hit Iran, the Cutting Sword of Justice, the ITSecTeam and Mersad campaign, the classic Zeus, SpyEye and Ice-IX botnets, Citadel, Reveton, Flashback, Nitol and DNSChanger have no object in the library's ATT&CK data; the library's S0041 "Wiper" is a different, 2013 Korean object (Demonstrated [116]).
- **Two sources came from copies.** Symantec's Elderwood paper was read from an Internet Archive copy, and the Global Payments press releases were read as exhibits to its SEC filings (Confirmed [46][8][9][10][11]).
- **What was not checked.** No primary was opened, or the page would not open, for: a Saudi Aramco or RasGas statement on Shamoon and the primary behind the 30,000-systems figure; the Defense Secretary's October 2012 speech; the New York Times and Guardian reporting of June 2012 on Stuxnet's origins; CISA's Shamoon joint analysis report; Kaspersky's miniFlame post; the name "Operation Ababil" at a primary; LinkedIn's own June 2012 blog post; Adobe's APSB12-03 and APSB12-18 and Oracle's Fusion Middleware advisory for CVE-2012-1710; Apple's later Flashback support pages; the Justice Department releases for the 2016 Iran and 2022 Center 16 cases and the Nikulin case; the 2012 Carberp arrests, the second Kelihos takedown and Grum; the South Carolina Department of Revenue, Zappos, Utah Department of Health, Yahoo Voices, eHarmony, Last.fm and Formspring incidents; the Symantec pcAnywhere source-code leak; the FBI and Scotland Yard call leak; the Gary McKinnon extradition decision; the European Cybercrime Centre's opening date; the Senate's second vote in November; the 2012 drafts of NIST SP 800-53 Rev. 4; ISO/IEC 27032:2012; EMET 3.0 and the BlueHat Prize; and FedRAMP's 2012 launch. They are left out or marked "not checked" where they touch a verified fact. Their absence here is not evidence that nothing happened.

## Part 1: the year as a dated timeline

One row per event or report. The date is the event date where the source gives one, otherwise the publication date. Rows marked "frame" or "boundary" open or close a 2012 event.

| Date | Event | Thread | Sector | Grade | Sources |
|---|---|---|---|---|---|
| 2011-12 (frame) | AntiSec hacks Stratfor (about 860,000 subscriber accounts), as charged in March 2012. Home: [Four Books on Cybercrime](/case-studies/CYBERCRIME_FOUR_BOOKS.md) | Hacktivism | Intelligence publishing | Confirmed (as charged) | [6][7] |
| 2011-12 to 2012-09 (frame) | Sporadic DDoS on US financial institutions, as alleged in 2016 | DDoS | Finance | Confirmed (as alleged) | [57] |
| 2011-12 (frame) | Earliest similar wiping incidents in Iran, per Kaspersky | Destructive | Not named | Confirmed (vendor's finding) | [19] |
| 2012-01-05 | Megaupload Limited, Vestor Limited and seven individuals indicted in E.D. Va. | Crime and courts | Media | Confirmed (as charged) | [1] |
| 2012-01-19 | Megaupload arrests in Auckland and more than 20 search warrants in the United States and eight countries; DHS and FBI guidance on recovering from malicious file erasure; Project Basecamp PLC disclosures at S4 | Crime and courts; Guidance; ICS | Media; Cross-sector; Energy, water | Confirmed | [1][86][82] |
| 2012-01-24 | US-CERT alert on Anonymous DDoS against government and entertainment sites after Megaupload (revised 26 Jan and 23 Apr) | Hacktivism | Government; media | Confirmed | [2] |
| 2012-01-25 | European Commission proposes the data protection Regulation and Directive | Policy | Cross-sector | Confirmed | [87] |
| 2012-01-31 | Theft of United Steelworkers e-mails, as alleged in the 2014 PLA indictment | Espionage (PLA, as charged) | Labor | Confirmed (as alleged) | [60] |
| 2012-02 | RFC 6520 TLS and DTLS Heartbeat Extension; Flashback spreads through older Java flaws, per Dr.Web | Standards; Malware | Internet; Consumer | Confirmed; Reported | [96][16] |
| 2012-02-16 | CVE-2012-0754 (Flash) published | Vulnerability | Cross-sector | Confirmed | [106] |
| 2012-02-27 to 2012-02-28 | CAPEC adds a compatibility section; CWE declares its first 13 compatible products | Standards | Software | Confirmed | [101][100] |
| 2012-03 (early) | Global Payments determines card data may have been accessed | Breach | Payments | Confirmed | [8] |
| 2012-03-05 | Judge extends the DNSChanger replacement-server order to 9 July; Hammond arrested in Chicago | Takedown; Crime and courts | Internet; Intelligence publishing | Confirmed | [3][6] |
| 2012-03-06 | SDNY charges five and unseals Monsegur's plea; FIPS 180-4 | Crime and courts; Standards | Multiple; Government | Confirmed | [6][7][94] |
| 2012-03-12 | FBI update: ISC to run clean DNS servers until 9 July | Takedown | Internet | Confirmed | [5] |
| 2012-03-13 | MS12-020: RDP CVE-2012-0002 and CVE-2012-0152 | Vulnerability | Cross-sector | Confirmed | [69][105] |
| 2012-03-16 | Flashback starts using CVE-2012-0507, per Dr.Web | Malware | Consumer | Reported | [16] |
| 2012-03-19 to 2012-03-25 | Microsoft's Operation b71: suit filed (19 Mar), Zeus-family servers seized (23 Mar), announced (25 Mar) | Takedown | Finance | Confirmed | [12] |
| 2012-03-25 | CAPEC 1.7 | Standards | Software | Confirmed | [101] |
| 2012-03-28 | European Commission proposes a European Cybercrime Centre at Europol | Policy | Cross-sector | Confirmed | [88] |
| 2012-03-30 | Global Payments 8-K: unauthorized access to a portion of its processing system, self-reported | Breach | Payments | Confirmed | [8] |
| 2012-04-01 | Global Payments: fewer than 1,500,000 card numbers may have been exported | Breach | Payments | Confirmed | [9] |
| 2012-04 (early) | Apple's Java updates fix CVE-2012-0507 (Dr.Web dates Apple's fix to 3 April); Dr.Web counts over 550,000 Flashback machines (4 Apr) | Vulnerability; Malware | Consumer | Confirmed; Reported | [17][16] |
| 2012-04-10 | MS12-027: CVE-2012-0158, limited targeted attacks known at release | Vulnerability | Cross-sector | Confirmed | [14][104] |
| 2012-04-13 | Access to ATI computers and theft of 7,000 or more credentials, as alleged | Espionage (PLA, as charged) | Metals | Confirmed (as alleged) | [60] |
| 2012-04-16 | US-CERT: Apple releases Flashback updates and a removal tool (updated 14 May) | Malware | Consumer | Confirmed | [15] |
| 2012-04-18 | APT1 spearphishes Mandiant staff with a fake CEO message | Espionage | Security vendor | Confirmed (vendor's finding) | [58] |
| 2012-04 | CVE-2012-0779 (Flash) first seen, per Symantec | Vulnerability | Cross-sector | Confirmed (vendor's finding) | [46] |
| 2012-04-21 to 2012-04-30 | Most of the Wiper incidents in Iran | Destructive | Not named | Confirmed (vendor's finding) | [19] |
| 2012-04-24 | US-CERT: DNSChanger-infected computers must be cleaned before 9 July | Takedown | Internet | Confirmed | [4] |
| 2012-04-26 | House passes H.R. 3523 (CISPA), 248 to 168 | Policy | Government | Confirmed | [89] |
| 2012-04-27 | CAPEC 1.7.1 | Standards | Software | Confirmed | [101] |
| 2012-05-03 | PHP-CGI query-string flaw made public (VU#520827); theft from SolarWorld executives, as alleged | Vulnerability; Espionage (PLA, as charged) | Web; Energy | Confirmed; Confirmed (as alleged) | [74][60] |
| 2012-05-04 | CVE-2012-0779 published | Vulnerability | Cross-sector | Confirmed | [62] |
| 2012-05-06 to 2012-05-08 | PHP says 5.3.12 and 5.4.2 were incomplete and ships 5.3.13 and 5.4.3 | Vulnerability | Web | Confirmed | [75] |
| 2012-05-08 | MS12-034 (including CVE-2011-3402) | Vulnerability | Cross-sector | Confirmed | [70] |
| 2012-05-09 to 2012-09-26 | At least twelve more SolarWorld intrusions, as alleged | Espionage (PLA, as charged) | Energy | Confirmed (as alleged) | [60] |
| 2012-05-15 | CWE 2.2 | Standards | Software | Confirmed | [100] |
| 2012-05 | Mofang active from May 2012, per ATT&CK | Espionage | Multiple | Confirmed (ATT&CK's description) | [67] |
| 2012-05-28 | Kaspersky publishes Flame. Home: [Stuxnet](/case-studies/STUXNET.md) | Espionage (no state named) | Middle East | Confirmed | [20] |
| 2012-05-31 | CrySyS sKyWIper report v1.05 | Espionage | Middle East; Hungary | Confirmed | [21] |
| 2012-06 | LinkedIn: about 6.5 million encrypted passwords stolen and published; Digital Bond spearphishing indicators (APT1, per Mandiant) | Breach; Espionage | Social network; ICS security | Confirmed | [29][28][58] |
| 2012-06-03 | Microsoft Advisory 2718704 revokes Enforced Licensing intermediate CAs | Trust | Software | Confirmed | [23][25] |
| 2012-06-04 | US-CERT alert on the unauthorized Microsoft certificates | Trust | Software | Confirmed | [24] |
| 2012-06-05 | Google posts "Security warnings for suspected state-sponsored attacks" | Espionage | Consumer | Confirmed (title and date) | [66] |
| 2012-06-06 | MSRC explains the collision attack used against the licensing certificates | Trust | Software | Confirmed | [26] |
| 2012-06-07 | CVE-2012-0507 published | Vulnerability | Cross-sector | Confirmed | [18] |
| 2012-06-11 | Kaspersky: a Stuxnet resource is a proto-Flame module | Espionage | Industrial | Reported | [27] |
| 2012-06-12 | MS12-037 (IE); Global Payments: exports did not exceed 1,500,000; CVE-2012-1875 published | Vulnerability; Breach | Cross-sector; Payments | Confirmed | [71][10][62] |
| 2012-06-13 | CVE-2012-1889 published; Advisory 2718704 revised | Vulnerability; Trust | Cross-sector; Software | Confirmed | [62][106][23] |
| 2012-06-16 | CVE-2012-1723 (Java) published | Vulnerability | Cross-sector | Confirmed | [18] |
| 2012-06-22 | US-CERT: active attacks on MSXML CVE-2012-1889; Fix it available | Vulnerability | Cross-sector | Confirmed | [30] |
| 2012-06-26 | Operation Card Shop arrests in 13 countries; FTC sues Wyndham | Crime and courts; Regulation | Payments; Hospitality | Confirmed | [32][80] |
| 2012-07 | First known adversarial access to OPM's network. Home: [The Hacker and the State](/case-studies/HACKER_AND_THE_STATE_CASES.md) | Espionage | Government | Confirmed | [81] |
| 2012-07 | Gauss command and control shut down, per Kaspersky | Espionage | Finance | Confirmed (vendor's finding) | [36] |
| 2012-07-09 | DNSChanger replacement DNS servers due to be turned off | Takedown | Internet | Confirmed | [3][4][5] |
| 2012-07-10 | MS12-043 fixes CVE-2012-1889; Adobe's later revocation covers software signed after this date | Vulnerability; Trust | Cross-sector | Confirmed | [31][51] |
| 2012-07-12 | Advisory 2728973 moves non-conforming intermediate CAs to the Untrusted store | Trust | Software | Confirmed | [33] |
| 2012-07-13 | ICS-CERT alert on Tridium Niagara AX with public proof of concept (date inferred from the alert code) | ICS | Building automation | Confirmed; date Inferred | [83] |
| 2012-07-17 | Kaspersky and Seculert publish the Madi campaign | Espionage (no attribution) | Middle East | Confirmed | [34] |
| 2012-07-26 | Global Payments completes its investigation; USD 84.4 million pre-tax charge | Breach | Payments | Confirmed | [11] |
| 2012-07-31 | Dropbox account takeovers disclosed. Home: [Cloud Security Incidents](/case-studies/CLOUD_SECURITY_INCIDENTS.md); Gauss at about 2,500 PCs in Kaspersky's data | Breach; Espionage | Cloud; Finance | Confirmed | [35][37] |
| 2012-08 | SP 800-61 Rev. 2; RFC 6698 DANE; DDoS on AT&T, as alleged; CVE-2012-1535 exploited in a Word document | Standards; DDoS; Vulnerability | Government; Telecom; Cross-sector | Confirmed; Confirmed (as alleged) | [91][97][57][38] |
| 2012-08-02 | Senate rejects cloture on S. 3414, the Cybersecurity Act of 2012 | Policy | Government | Confirmed | [90] |
| 2012-08-09 | Kaspersky publishes Gauss; FBI warns of Reveton | Espionage; Ransomware | Finance; Consumer | Confirmed | [36][37][77] |
| 2012-08-14 | Advisory 2661254: minimum RSA key length of 1024 bits | Trust | Cross-sector | Confirmed | [103] |
| 2012-08-15 | CVE-2012-1535 published; ICSA-12-228-01 on Tridium | Vulnerability; ICS | Cross-sector; Building automation | Confirmed | [62][83] |
| 2012-08-16 | Kaspersky analyses Shamoon | Destructive | Not named | Confirmed | [39] |
| 2012-08-26 to 2012-08-30 | Java 7 CVE-2012-4681: public (26 Aug), TA12-240A (27 Aug), NVD (28 Aug), Oracle Security Alert (30 Aug) | Vulnerability | Cross-sector | Confirmed | [42][41][44][43] |
| 2012-08-29 | Kaspersky's account of Wiper | Destructive | Not named | Confirmed | [19] |
| 2012-09 | DDoS on US banks becomes near-weekly, as alleged; Epic Turla payload compiled and log entry of 19 Sep, per Kaspersky's 2014 report | DDoS; Espionage | Finance; Government | Confirmed (as alleged); Confirmed | [57][64] |
| 2012-09-06 | Symantec publishes "The Elderwood Project" | Espionage | Defense; NGOs | Confirmed | [46][45] |
| 2012-09-10 | Telvent Canada learns of a breach of its OASyS SCADA project files; Microsoft obtains the Nitol order | ICS; Takedown | Energy; Consumer | Reported; Confirmed | [84][58][13] |
| 2012-09-15 | CRIME, CVE-2012-4929, published | Vulnerability | Internet | Confirmed | [107] |
| 2012-09-17 to 2012-09-21 | IE CVE-2012-4969: Advisory 2757760 (17 Sep), NVD (18 Sep), Fix it (19 Sep), MS12-063 (21 Sep) | Vulnerability | Cross-sector | Confirmed | [47][49][48] |
| 2012-09-17 | SP 800-30 Rev. 1 | Standards | Government | Confirmed | [92] |
| 2012-09-21 | US-CERT: increased exploitation of WordPress and Joomla | Vulnerability | Web | Confirmed | [50] |
| 2012-09-28 | US-CERT: an Adobe code-signing certificate signed malicious code; revocation set for 4 Oct | Trust | Software | Confirmed | [51] |
| 2012-10 | Kaspersky begins the Red October investigation; RFC 6749 OAuth 2.0 | Espionage; Standards | Diplomatic; Internet | Confirmed | [63][98] |
| 2012-10-02 | NIST selects Keccak as SHA-3 | Standards | Cross-sector | Confirmed | [95] |
| 2012-10-24 | Barnes & Noble discloses tampered PIN pads | Breach | Retail | Confirmed | [54] |
| 2012-10-30 | CWE 2.3; 20 compatible products | Standards | Software | Confirmed | [100] |
| 2012-11 | RFC 6797 HSTS | Standards | Web | Confirmed | [99] |
| 2012-11-08 | PNC 10-Q describes the DDoS disruption | DDoS | Finance | Confirmed | [52] |
| 2012-12-03 to 2012-12-14 | ITU WCIT-12 in Dubai | Policy | Telecom | Confirmed | [93] |
| 2012-12-11 | MS12-083, the year's last bulletin | Vulnerability | Cross-sector | Confirmed | [72] |
| 2012-12-30 | CVE-2012-4792 (IE) published | Vulnerability | Cross-sector | Confirmed | [73] |
| 2013-02 (boundary) | LinkedIn 10-K (19 Feb); Mandiant APT1 report; Capital One 10-K (28 Feb) | Breach; Espionage; DDoS | Multiple | Confirmed | [28][58][53] |
| 2013-06 (boundary) | Microsoft, the FBI and partners disrupt Citadel, which had delivered Reveton | Takedown | Finance | Confirmed | [78] |
| 2014-05 (boundary) | W.D. Pa. indictment of five PLA officers (returned 1 May) | Espionage | Multiple | Confirmed (as charged) | [59][60] |
| 2016-01-21 (boundary) | SDNY indictment of seven Iranians for the 2011 to 2013 DDoS | DDoS | Finance | Confirmed (as charged) | [56] |
| 2021-11-03 to 2026-04-13 (boundary) | KEV adds the 22 CVE-2012 entries | Vulnerability | Cross-sector | Confirmed | [55] |

The Bowman Avenue Dam intrusion charged against Hamid Firoozi happened in late 2013, so it is not a 2012 event and is not in this timeline (Confirmed [85]).

## Part 2: Flame, Gauss and the certificate response (summary)

The [Stuxnet](/case-studies/STUXNET.md) study is the home for Flame, Gauss and Advisory 2718704, and it records the 2012 sequence: Kaspersky's first Flame Q&A of 28 May, Advisory 2718704 of 3 June graded with the Flame link Inferred, Kaspersky's resource 207 finding of 11 June and the Gauss report of 9 August (Confirmed that the home study carries them [115]). The [United States-attributed threat actors](/case-studies/THREAT_ACTORS_UNITED_STATES.md) study carries Flame as well (Confirmed [115]). This chronicle summarizes the year's record.

Kaspersky says the ITU asked it to find a wiper deleting data in the Middle East, and that the search found Flame (Confirmed [20]). Its Q&A of 28 May dates Flame's use to at least August 2010 and its presence in the wild to February or March 2010, puts most targets in Iran, Lebanon, Syria and Israel, and describes a toolkit of about 20 modules and about 20 MB when fully deployed, about 20 times larger than Stuxnet, with no major code similarity to Stuxnet or Duqu (Confirmed [20]). It spreads through MS10-061 and removable-media modules and captures audio, screenshots, network traffic, keystrokes and Bluetooth device data (Confirmed [20]). Kaspersky says nothing ties Flame to a specific nation state but that it most likely belongs to nation-state actors (Confirmed that Kaspersky says so [20]; the judgment is Reported). CrySyS Lab's sKyWIper report v1.05 of 31 May describes a modular information stealer possibly active for five to eight years or more, with infections including Hungary, and identifies it as the malware Iran's CERT (MAHER) called Flamer (Confirmed [21]). On 11 June Kaspersky reported that resource 207 in the 2009 Stuxnet is a proto-Flame module and that the Flame and Stuxnet/Duqu teams shared code in 2009 before their platforms evolved separately (Reported [27]).

ATT&CK's [S0143 Flame](/mitre/software/S0143.md), aliases Flamer and sKyWIper, was used to collect information since at least 2010, mostly in the Middle East, with no associated group; it lists ten Enterprise techniques and two ICS techniques, all bound in Part 12 (Confirmed [22]; Demonstrated [116]).

Microsoft's Advisory 2718704 of 3 June reports active attacks using unauthorized certificates derived from a Microsoft CA and moves two Microsoft Enforced Licensing Intermediate PCA certificates and the Microsoft Enforced Licensing Registration Authority CA (SHA1) to the Untrusted store; it is cumulative with the 2011 advisories 2524375, 2607712 and 2641690 and was revised on 13 June (Confirmed [23]). It does not name Flame (Confirmed [23]). The MSRC blog of the same day calls Flame complex targeted malware and says the Terminal Server Licensing Service issued certificates, using an older cryptographic algorithm, that could sign code as Microsoft, and that the service no longer issues certificates that allow code signing (Confirmed [25]). On 6 June MSRC explained that the attacker needed an MD5 collision to forge a Terminal Server licensing certificate valid for code signing on Vista and later, and that Microsoft invalidated the whole licensing CA hierarchy (Confirmed [26]). US-CERT alerted on 4 June (Confirmed [24]). On 12 July Advisory 2728973 moved further intermediate CA certificates that did not meet Microsoft's PKI standards to the Untrusted store; the US-CERT notice does not mention Flame (Confirmed [33]). ATT&CK's S0143 records no code-signing technique, so the code-signing binding in Part 12 is this study's (Confirmed [26]; Inferred).

Kaspersky's Gauss research of 9 August describes a toolkit built on the Flame platform, created around mid-2011, whose command and control was shut down in July 2012 (Confirmed [36]). It steals online-banking credentials for Lebanese banks, including Bank of Beirut, Byblos Bank and Fransabank, and targets Citibank and PayPal users; it also takes browser data and infects USB drives, with a USB module that uses the .LNK flaw CVE-2010-2568 (Confirmed [36][37]). Kaspersky's telemetry showed about 2,500 infected PCs in 25 countries by 31 July, about 1,660 of them in Lebanon, and Kaspersky estimates tens of thousands in all (Confirmed as Kaspersky's counts [36][37]). Kaspersky calls Gauss "most likely a nation-state sponsored operation" and the first publicly known nation-state banking Trojan; that is the vendor's assessment (Reported [37]). ATT&CK has no Gauss object (Demonstrated [116]). CVE-2010-2568 was added to KEV on 15 September 2022 (Confirmed [55]).

## Part 3: Wiper and Shamoon (summary)

The [Iran-attributed threat actors](/case-studies/THREAT_ACTORS_IRAN.md) study and section 3.2 of [The Hacker and the State](/case-studies/HACKER_AND_THE_STATE_CASES.md) are the homes for Shamoon (Confirmed [115]).

Kaspersky's account of 29 August says destructive malware it calls Wiper destroyed data on systems in Iran in April 2012, mostly between 21 and 30 April, with similar incidents back to December 2011; the ITU asked Kaspersky to investigate, no complete sample was recovered, and in Kaspersky's firm opinion Wiper is not Flame (Confirmed [19]). Kaspersky gives no attribution (Confirmed [19]). ATT&CK's S0041 "Wiper" is a different object, tied to Korea in 2013, and is not bound to this event (Demonstrated [116]).

Kaspersky's Shamoon analysis of 16 August, updated 17 August, describes samples whose PDB path names Shamoon and ArabianGulf: a 900 KB executable with XOR-encrypted resources that carries a raw-disk driver signed by EldoS Corporation and uses it to overwrite the master boot record (Confirmed [39]). Kaspersky judges it "more likely" a copycat of Wiper, probably only used in very focused targeted attacks, gives no state attribution and does not name a victim (Confirmed [39]). ATT&CK's [S0140 Shamoon](/mitre/software/S0140.md), alias Disttrack, is a wiper, and the page names no victim (Confirmed [40]). ATT&CK records Shamoon as first used in 2012 by an Iranian group known as the Cutting Sword of Justice (Confirmed that ATT&CK says so [40]; the attribution is Reported). Of its 24 techniques, only T1485 Data Destruction and T1561.002 Disk Structure Wipe cite Symantec's report of 16 August 2012; the rest cite 2016 or 2018 sources on Shamoon 2 and 3, so only those two are bound to 2012 (Confirmed [40]; Demonstrated [116]). The home studies record Unit 42's later description of the 2012 target as a Saudi energy company with 30,000 or more systems damaged; no primary for the figure was opened (Reported [115]). DHS and the FBI had already published guidance on 19 January on recovering from the malicious erasure of files, including keeping backups in a separate, secure location (Confirmed [86]).

## Part 4: the state and espionage record

### Elderwood and the 2012 zero-days

Symantec's "The Elderwood Project" of 6 September says the group behind the 2009 Hydraq (Aurora) attack shifted to watering-hole attacks and used 2012 zero-days CVE-2012-0779 (first seen April 2012), CVE-2012-1875, CVE-2012-1889 and CVE-2012-1535, three of them within 30 days, and that it compromised the Amnesty International Hong Kong website again (Confirmed [46]). Symantec says only a large criminal organization or a nation state, or attackers it supports, could provide such resources, and names no state (Confirmed that Symantec says so [46]). The CVE records give publication dates of 4 May (CVE-2012-0779), 12 June (CVE-2012-1875), 13 June (CVE-2012-1889) and 15 August (CVE-2012-1535) (Confirmed [62]). CVE-2012-1889 and CVE-2012-1535 are in KEV; CVE-2012-0779 and CVE-2012-1875 are not (Confirmed [55]).

ATT&CK's [G0066 Elderwood](/mitre/groups/G0066.md) is a suspected Chinese espionage group reportedly responsible for Aurora, described from Symantec, Security Affairs and Christian Science Monitor reporting of September 2012; it targets defense, supply chain, NGOs and IT providers and lists nine techniques and the software [S0203 Hydraq](/mitre/software/S0203.md), [S0012 PoisonIvy](/mitre/software/S0012.md), [S0204 Briba](/mitre/software/S0204.md), [S0205 Naid](/mitre/software/S0205.md), [S0206 Wiarp](/mitre/software/S0206.md), [S0207 Vasport](/mitre/software/S0207.md), [S0208 Pasam](/mitre/software/S0208.md), [S0210 Nerex](/mitre/software/S0210.md) and [S0211 Linfo](/mitre/software/S0211.md) (Confirmed [45]; names Demonstrated [116]). The China attribution is ATT&CK's description, not a government finding (Reported [45]). The homes are [China-attributed threat actors](/case-studies/THREAT_ACTORS_CHINA.md) and [The Zero-Day Market](/case-studies/ZERO_DAY_MARKET_EVENTS.md), which carries Aurora (Confirmed [115]).

### APT1 in 2012

Mandiant's APT1 report, published in February 2013, says APT1 compromised 141 companies in 20 industries since 2006 and that Mandiant "believes" APT1 is PLA Unit 61398, naming one unlikely alternative; it counts 1,905 Remote Desktop logins to APT1's attack infrastructure between January 2011 and January 2013 (Confirmed as Mandiant's findings [58]). The report describes APT1's attempt on Mandiant itself on 18 April 2012: a message from a free-webmail account impersonating Mandiant's CEO linked to a ZIP file carrying the WEBC2-TABLE backdoor, and no one clicked (Confirmed [58]). Mandiant attributes to APT1, by tools and infrastructure, the Telvent Canada breach reported in September 2012 and the indicators from the June 2012 spearphishing of Digital Bond (Confirmed as Mandiant's attribution [58]). ATT&CK's [G0006 APT1](/mitre/groups/G0006.md) lists T1566.002 Spearphishing Link and T1585.002 Email Accounts for the group (Confirmed [61]).

On 1 May 2014 a grand jury in the Western District of Pennsylvania indicted five officers of 3PLA, Second Bureau, Third Office (MUCD 61398) on 31 counts covering intrusions at six US companies (Confirmed as charged [59]). Three alleged 2012 acts follow trade events (Confirmed as alleged [60]):

| Date (about) | Victim | Alleged act | Context the indictment gives |
|---|---|---|---|
| 2012-01-31 | United Steelworkers | Theft of e-mails dated 24 to 31 January from six senior USW employees | The day after USW's public statements on WTO and auto-parts trade |
| 2012-04-13 | ATI | Access to ATI computers and theft of usernames and passwords for at least 7,000 employees; the hosts beaconed to the same hop point in May 2012 | The day after a joint-venture board meeting in Shanghai |
| 2012-05-03, then 2012-05-09 to 2012-09-26 | SolarWorld | Theft of e-mails and files of three senior executives, then at least twelve more intrusions | During the solar trade case |

ATT&CK lists T1114.002 Remote Email Collection for APT1; binding it to the USW and SolarWorld thefts is this study's reading (Confirmed [61]; Inferred). The home is [China-attributed threat actors](/case-studies/THREAT_ACTORS_CHINA.md) (Confirmed [115]).

### Madi

Kaspersky and Seculert published the Madi campaign on 17 July: Delphi backdoors delivered by social engineering, including spearphishing .pps slideshows and right-to-left-override filenames, reached about 800 victims mainly in Iran, Israel and Afghanistan over almost a year (Confirmed [34]). Targets included critical-infrastructure engineering firms, government agencies, financial houses and academia, and the report gives no attribution (Confirmed [34]). The library's ATT&CK data has no Madi object (Demonstrated [116]).

### Red October and Epic Turla

Kaspersky says its Red October investigation began in October 2012 after attacks on diplomatic agencies, and that the network had been active since about 2007 against diplomatic, government and research targets in Eastern Europe, the former Soviet states and Central Asia; Kaspersky "strongly believe[s]" the attackers have Russian-speaking origins, and the library's ATT&CK data has no object for it (Demonstrated [116]; the origin judgment is Reported [63]). Kaspersky's 2014 Epic Turla report dates samples and logs to 2012, including a payload compiled in September 2012 and a log entry of 19 September 2012, and describes several hundred computers in more than 45 countries hit through watering holes and spearphishing, linked to Turla's Carbon ([G0010](/mitre/groups/G0010.md), [S0335 Carbon](/mitre/software/S0335.md)) and with no sponsor named (Confirmed [64]). That the operation began in 2012 is this study's inference (Inferred [64]). The home is [Russia-attributed threat actors](/case-studies/THREAT_ACTORS_RUSSIA.md), which carries Epic Turla from September 2012 (Confirmed [115]).

### Objects first dated to 2012 and those that are not

ATT&CK describes these groups as active since at least 2012 (Mofang since at least May 2012): [G0021 Molerats](/mitre/groups/G0021.md), [G0038 Stealth Falcon](/mitre/groups/G0038.md), [G0056 PROMETHIUM](/mitre/groups/G0056.md), [G0067 APT37](/mitre/groups/G0067.md), [G0070 Dark Caracal](/mitre/groups/G0070.md), [G0093 GALLIUM](/mitre/groups/G0093.md), [G0094 Kimsuky](/mitre/groups/G0094.md), [G0096 APT41](/mitre/groups/G0096.md), [G0103 Mofang](/mitre/groups/G0103.md) (from May 2012), [G0121 Sidewinder](/mitre/groups/G0121.md), [G0123 Volatile Cedar](/mitre/groups/G0123.md), [G0129 Mustang Panda](/mitre/groups/G0129.md) and [G1034 Daggerfly](/mitre/groups/G1034.md); [G0131 Tonto Team](/mitre/groups/G0131.md)'s Heartbeat Campaign ran from 2009 to 2012 (Confirmed [67][109]; Demonstrated [117]). These are first-observed claims, not dated 2012 events, so none of their techniques is bound here (Confirmed [67]; Inferred). The [APT41](/case-studies/APT41_PUBLIC_RECORD.md) study is the home for APT41 from 2012 (Confirmed [115]). ATT&CK's [C0016 Operation Dust Storm](/mitre/campaigns/C0016.md) runs from January 2010 to February 2016 and so spans 2012 (Confirmed [110]).

The UK says it is "almost certain" that FSB Centre 16 is the actor known as Energetic Bear, Berserk Bear or Crouching Yeti, and ATT&CK's [G0035 Dragonfly](/mitre/groups/G0035.md) is active since at least 2010 and attributed to FSB Center 16; neither page carries a 2012 date (Confirmed [65]; Demonstrated [116]). ATT&CK's [G0003 Cleaver](/mitre/groups/G0003.md) is attributed to Iranian actors but gives no active dates, so no Cleaver activity is dated to 2012 here (Confirmed [68]). Google's Online Security Blog posted "Security warnings for suspected state-sponsored attacks" on 5 June; only the title and date were checked (Confirmed [66]).

### OPM's first known access

The House Oversight committee's timeline puts the first known adversarial access to OPM's network in July 2012, a date established from malware found in 2015 (Confirmed [81]). Section 2.1 of [The Hacker and the State](/case-studies/HACKER_AND_THE_STATE_CASES.md) is the home (Confirmed [115]).

## Part 5: denial of service against banks and governments

### The financial-sector campaign

PNC's 10-Q of 8 November describes a well-publicized series of apparently related denial-of-service attacks on large financial services companies, including PNC, that temporarily disrupted customers' access to its corporate website and online banking, with no customer data lost (Confirmed [52]). Capital One's 10-K of 28 February 2013 says it and other US financial services providers were targeted on several occasions by sophisticated third parties and that at least once this disrupted consumer online banking (Confirmed [53]). Neither filing names an attacker (Confirmed [52][53]).

The FBI says a grand jury in the Southern District of New York indicted seven Iranian nationals on 21 January 2016, managers or employees of ITSecTeam or Mersad, private security companies working for the Iranian Government including the IRGC, for a coordinated DDoS campaign against the US financial sector from 2011 through 2013 (Confirmed as charged [56]). The indictment alleges that the attacks began around December 2011, were sporadic until September 2012 and then ran near-weekly through about May 2013 at up to about 140 Gbps, against at least 46 major financial institutions on at least 176 days; that targets from December 2011 to at least December 2012 included Bank of America, NASDAQ, NYSE, Capital One, ING, BB&T, FIS, U.S. Bank and PNC; and that the defendants ran a series of DDoS attacks on AT&T in or about August 2012 (Confirmed as alleged [57]). The [2016 chronicle](/case-studies/CHRONICLE_2016.md) records the indictment's unsealing on 24 March 2016, and the home for the actors is [Iran-attributed threat actors](/case-studies/THREAT_ACTORS_IRAN.md) (Confirmed [115]). The campaign name "Operation Ababil" was not checked against a primary. ATT&CK has no object for this campaign; T1498 Network Denial of Service is assigned from the indictment's description (basis Described) and T1584.005 Botnet is this study's reading (basis Inferred); both bindings are Inferred [57]; Demonstrated [116].

### Anonymous and the Megaupload shutdown

US-CERT's alert of 24 January, revised on 26 January and 23 April, describes coordinated DDoS allegedly promoted by Anonymous in response to the Megaupload shutdown and in protest of SOPA and PIPA against US government agency and entertainment-industry websites; US-CERT saw HTTP GET floods and a UDP flood and reviewed variants of the Low Orbit Ion Cannon (Confirmed [2]). Those two floods map to T1499.002 Service Exhaustion Flood and T1498.001 Direct Network Flood (basis Described in Part 12) (Inferred [2]).

## Part 6: payment, password and account breaches

### Global Payments

The [E-Commerce Threats](/case-studies/ECOMMERCE_THREATS.md) study does not cover the Global Payments breach, so this chronicle is its home (Inferred from a search of that study [115]). Global Payments' 8-K of 30 March says it identified and self-reported unauthorized access into a portion of its processing system, that in early March it determined card data may have been accessed, and that it engaged IT forensics experts and contacted federal law enforcement (Confirmed [8]). Its update of 1 April says the affected portion was confined to North America, fewer than 1,500,000 card numbers may have been exported, Track 2 card data may have been stolen, and cardholder names, addresses and Social Security numbers were not obtained; the company believed the incident contained (Confirmed [9]). On 12 June it said exported card numbers did not exceed 1,500,000, limited to Track 2 data from part of its North American system, and that the investigation had also found potential unauthorized access to servers holding personal information of a subset of US merchant applicants (Confirmed [10]). On 26 July it said the investigation was complete and that fiscal 2012 results include a USD 84.4 million pre-tax charge for estimated card brand charges and investigation and remediation expenses, with a qualified security assessor conducting the independent review (Confirmed [11]). None of the filings opened describes how the intruders got in, so no technique is bound (Confirmed [8][9][10][11]; Inferred).

### LinkedIn

LinkedIn's 10-Q for the second quarter of 2012 and its 10-K filed on 19 February 2013 say that in June 2012 about 6.5 million members' encrypted passwords were stolen and published on an unauthorized website (Confirmed [29][28]). The filings opened describe no intrusion method, and LinkedIn's own June 2012 blog post was not opened, so no technique is bound (Confirmed [28][29]; not checked).

### Dropbox (summary)

The [Cloud Security Incidents](/case-studies/CLOUD_SECURITY_INCIDENTS.md) study is the home. Dropbox said on 31 July that usernames and passwords stolen from other websites were used to sign in to a small number of Dropbox accounts, and that a stolen password opened an employee's account holding a project document with user e-mail addresses, which Dropbox believes led to spam; it announced two-factor authentication (Confirmed [35]). The home study records Dropbox confirming in 2016 that a set of about 68 million credentials was likely obtained in 2012 (Confirmed that the home study carries it [115]). The home study maps the 2012 pattern to T1110.004 Credential Stuffing, and this chronicle binds that and T1078 Valid Accounts for the employee account (the binding is Inferred; basis Described [35][115]).

### Barnes & Noble

Barnes & Noble's 10-Q of 6 December says PIN pads in certain stores were tampered with to allow criminal access to card data and PINs, that it disclosed this publicly on 24 October, and that putative class actions followed (Confirmed [54]). ATT&CK has no technique that names point-of-sale hardware tampering, so none is bound (Inferred).

### Wyndham (summary)

The FTC sued Wyndham Worldwide and three subsidiaries in the District of Arizona on 26 June, alleging data security failures in which three breaches from April 2008 to late 2009 exposed more than 500,000, more than 50,000 and about 69,000 payment card accounts, exported to a domain registered in Russia (Confirmed as alleged [80]). The breaches predate 2012; the action is the year's event. The home is [E-Commerce Threats](/case-studies/ECOMMERCE_THREATS.md), which carries the breaches and the 2015 rulings (Confirmed [115]).

## Part 7: the vulnerability record

### Exploited at or before the fix

The year's flaws for which the record shows exploitation in 2012, plus the KEV and Elderwood entries without a 2012 exploitation date, in date order:

| CVE | Product and flaw | First notice | Exploitation in the record | Fix | CWE (source) | KEV | Sources |
|---|---|---|---|---|---|---|---|
| CVE-2012-0754 | Adobe Flash Player | NVD 16 Feb | No 2012 date in the record; KEV-listed | Adobe's bulletin not opened | CWE-787 (NVD) | 2022-06-08 | [106][55] |
| CVE-2012-0507 | Oracle Java SE (7u2, 6u30, 5.0u33 and earlier) | Apple's Java updates (no date on the page); NVD 7 Jun | Flashback from 16 March, per Dr.Web | Java 1.6.0_31 for OS X (HT5228); Oracle's fix not opened | CWE-843 (NVD) | 2022-03-03, known ransomware use | [16][17][18][55] |
| CVE-2012-0158 | Office and SQL Server common controls (MSCOMCTL.OCX) | MS12-027, 10 Apr | Limited, targeted attacks known at release | MS12-027 | CWE-94 (NVD) | 2021-11-03, known ransomware use | [14][104][55] |
| CVE-2012-0779 | Adobe Flash Player | First seen April 2012 (Symantec); CVE published 4 May | A 2012 zero-day used by Elderwood | not opened | not checked | not in KEV | [46][62][55] |
| CVE-2012-1823 | PHP-CGI query-string handling | VU#520827, public 3 May | No 2012 date in the record; KEV-listed | PHP 5.3.12 and 5.4.2 incomplete; 5.3.13 and 5.4.3 (8 May, with CVE-2012-2311); mod_php and php-fpm not affected | CWE-77 (NVD) | 2022-03-25 | [74][75][55] |
| CVE-2012-1875 | Internet Explorer | CVE published 12 Jun | A 2012 zero-day used by Elderwood | not checked | not checked | not in KEV | [46][62][55] |
| CVE-2012-1889 | Microsoft XML Core Services | CVE published 13 Jun; US-CERT 22 Jun | Active attacks through compromised websites and Office documents (Microsoft, Google, Sophos); used by Elderwood | Fix it (Advisory 2719615); MS12-043, 10 Jul | CWE-787 (NVD and the CVE record's CISA ADP) | 2022-06-08 | [30][31][62][106][46][55] |
| CVE-2012-1723 | Oracle Java SE | NVD 16 Jun | No 2012 date in the record; KEV-listed | not opened | CWE-284 (NVD) | 2022-03-03, known ransomware use | [18][55] |
| CVE-2012-1535 | Adobe Flash Player | CVE published 15 Aug | Exploited in the wild in August with SWF content in a Word document; used by Elderwood | not opened | CWE-20 (NVD); CWE-94 and CWE-20 (CVE record, CISA ADP) | 2022-03-03 | [38][62][46][55] |
| CVE-2012-4681 | Oracle Java SE 7 Update 6 and earlier, SecurityManager bypass | VU#636312 public 26 Aug; TA12-240A 27 Aug | Actively exploited with public exploit code | Oracle Security Alert, 30 Aug; Java 7u7 | CWE-284 and NVD-CWE-Other (NVD) | 2022-03-03, known ransomware use | [42][41][44][43][55] |
| CVE-2012-4969 | Internet Explorer 6 to 9, execCommand use after free | Advisory 2757760, 17 Sep; NVD 18 Sep | Exploited in the wild in September | Fix it 19 Sep; MS12-063, 21 Sep | CWE-416 (NVD) | 2022-06-08 | [47][49][48][55] |
| CVE-2012-0391 | Apache Struts 2 (S2-008) | S2-008 | No 2012 date in the record; KEV-listed | Struts 2.3.18 | not checked | 2022-01-21 | [76][55] |
| CVE-2012-4792 | Internet Explorer 6 to 8, use after free | NVD 30 Dec | No 2012 date in the record; KEV-listed | not opened | CWE-416 (NVD) | 2024-07-23 | [73][55] |

Flashback's older Java entry points, CVE-2011-3544 and CVE-2008-5353, are Dr.Web's account (Reported [16]).

In ATT&CK terms the browser and plug-in flaws read as T1189 Drive-by Compromise and T1203 Exploitation for Client Execution, the document flaws as T1203 and, where a sender delivered the file, T1566.001 Spearphishing Attachment, and the PHP-CGI and Struts flaws as T1190 Exploit Public-Facing Application; MS12-027 says "limited, targeted attacks" without naming the vector, so its T1566.001 pairing is this study's (Inferred [14]).

### The year's Java problem

Three of the five 2012 KEV entries with known ransomware use are Java flaws: CVE-2012-0507, CVE-2012-1723 and CVE-2012-4681 (Confirmed [55]). Dr.Web says the BackDoor.Flashback Mac botnet passed 550,000 machines, mostly in the United States and Canada, spreading through CVE-2011-3544 and CVE-2008-5353 from February and through CVE-2012-0507 after 16 March (Reported [16]). Apple's Java for OS X Lion 2012-002 and Java for Mac OS X 10.6 Update 7 moved Java to 1.6.0_31 and fixed CVE-2012-0507, which let an untrusted applet run code outside the sandbox; the page carries no date, and Dr.Web dates Apple's fix to 3 April (Confirmed [17]; Reported [16]). US-CERT's alert of 16 April, updated 14 May, says Apple released security updates and a Flashback removal tool for OS X 10.7.3 and 10.6.8, later extended to 10.5 (Confirmed [15]).

For CVE-2012-4681, CERT/CC's VU#636312 says Oracle's Java 7 runtime failed to restrict access to privileged code, gives a Date Public of 26 August and a first publication of 27 August, and credits FireEye with the public report (Confirmed [42]). US-CERT's TA12-240A of 27 August, updated 28 August and 5 September, says the Security Manager bypass was being actively exploited with public exploit code and advises disabling Java in browsers (Confirmed [41]). Oracle's Security Alert of 30 August fixes three vulnerabilities and one security-in-depth issue in browser Java, remotely exploitable without authentication, and references TA12-240A; the fix shipped in Java 7u7 (Confirmed [43][41]).

### Microsoft's year in bulletins

MS12-020 of 13 March, rated Critical, fixed the RDP remote code execution flaw CVE-2012-0002, reported by Luigi Auriemma through ZDI, and the Terminal Server denial of service CVE-2012-0152; RDP is off by default, NVD lists CWE-94, and CVE-2012-0002 is not in KEV, with no exploitation in the record (Confirmed [69][105][55]). MS12-034 of 8 May fixed three publicly disclosed and seven privately reported flaws across Office, Windows, .NET and Silverlight, including TrueType font handling, and its CVE list includes CVE-2011-3402 (Confirmed [70]). MS12-037 of 12 June was a cumulative Internet Explorer update for one publicly disclosed and twelve privately reported flaws (Confirmed [71]). MS12-063 was published on Friday 21 September, outside the second-Tuesday cycle, which makes it an out-of-band release; the bulletin does not use that phrase (Confirmed [48]; Inferred). It fixed CVE-2012-4969 with four other IE CVEs; Advisory 2757760 had assigned the CVE with a corrected EMET workaround on 18 September and offered a Fix it on 19 September (Confirmed [47]). MS12-001 was published on 10 January and MS12-083, an Important IP-HTTPS revoked-certificate bypass (CVE-2012-2549), on 11 December; MS12-084 returns no page, so the year carried 83 bulletins by numbering (Confirmed [72]; the count is Inferred).

### Certificates and code signing

Besides 2718704 and 2728973 (Part 2), Microsoft's Advisory 2661254 of 14 August made Windows stop trusting certificates with RSA keys under 1024 bits in any chain built through CertGetCertificateChain, covering TLS, signed code, encrypted mail and private PKIs; it was revised on 11 September and offered through automatic updating from 9 October, and logging of blocked certificates is available but off by default (Confirmed [103]). US-CERT said on 28 September that an Adobe code-signing certificate had been used to sign malicious code and that Adobe would revoke it on 4 October for software signed after 10 July (Confirmed [51]).

### Web platforms and CRIME

US-CERT reported on 21 September that exploitation of WordPress and Joomla had increased and that compromised sites hosted content that infected visitors or enabled denial of service against others; a later update stressed Joomla in an ongoing campaign (Confirmed [50]). No source opened links this to the bank DDoS (Confirmed [50]). PHP's 2012 news says 5.3.12 and 5.4.2 did not fix every variation of CVE-2012-1823 and that 5.3.13 and 5.4.3 of 8 May completed the CGI fix as CVE-2012-2311 (Confirmed [75]). Apache's S2-008 covers CVE-2012-0391 to CVE-2012-0394 in Struts 2.0.0 to 2.3.17, fixed in 2.3.18 (Confirmed [76]). CVE-2012-4929, CRIME, published on 15 September with CWE-310, describes how TLS 1.2 and earlier can compress data before encryption without hiding its length, letting a man in the middle recover plaintext HTTP headers; NVD records no exploitation and it is not in KEV (Confirmed [107][55]).

### The year's CVE volume

A query of NVD by publication date returns 5,351 CVE records published during 2012, in four windows of 1,293, 1,993, 2,014 and 51 records; that is a query result by publication date, not a count of CVE-2012 ids (Confirmed [108]).

### The KEV tail

The KEV catalog, version 2026.11.10, lists 22 CVE-2012 entries across Microsoft, Oracle Java and Fusion Middleware, Adobe Flash, PHP and Struts, with dates added from 3 November 2021 to 13 April 2026; those are additions, not exploitation dates (Confirmed [55]). Five are marked with known ransomware use: CVE-2012-0158, CVE-2012-0507, CVE-2012-1710, CVE-2012-1723 and CVE-2012-4681 (Confirmed [55]). The entries named in the record opened here:

| KEV dateAdded | CVE-2012 ids |
|---|---|
| 2021-11-03 | CVE-2012-0158 |
| 2022-01-21 | CVE-2012-0391 |
| 2022-03-03 | CVE-2012-0507, CVE-2012-1535, CVE-2012-1723, CVE-2012-4681 |
| 2022-03-25 | CVE-2012-1823 |
| 2022-06-08 | CVE-2012-0754, CVE-2012-1889, CVE-2012-4969 |
| 2024-07-23 | CVE-2012-4792 |

So 2012 exploitation is recorded mainly in vendor advisories, US-CERT alerts and NVD's "exploited in the wild" text, and KEV added the year's entries nine to fourteen years later (Confirmed [55]; Inferred for the reading). The [Other states' threat actors](/case-studies/THREAT_ACTORS_OTHER_STATES.md) and [APT41](/case-studies/APT41_PUBLIC_RECORD.md) studies record CVE-2012-0158 still in use by later groups (Confirmed [115]).

## Part 8: crimeware, takedowns and the courts

### Megaupload

The Justice Department and FBI announced on 19 January that seven individuals and two corporations, Megaupload Limited and Vestor Limited, had been indicted in the Eastern District of Virginia on 5 January for racketeering, copyright and money-laundering conspiracies (Confirmed as charged [1]). The release says four defendants were arrested in Auckland, more than 20 search warrants were executed in the United States and eight countries, about USD 50 million in assets was seized and 18 domains were ordered seized, and it alleges more than USD 175 million in proceeds and more than USD 500 million in harm to copyright owners (Confirmed that the government says so [1]; the figures are allegations).

### DNSChanger ends

US-CERT reported that the court order running the FBI's replacement DNS servers was due to expire on 8 March and that a federal judge extended it on 5 March to 9 July (Confirmed [3]). The FBI's Operation Ghost Click page, updated 12 March, says the order authorized ISC to run temporary clean DNS servers for DNSChanger victims until 9 July; the FBI says the ring had infected about four million computers in more than 100 countries from 2007, about 500,000 in the United States including at NASA, and made at least USD 14 million in illicit advertising fees (Confirmed [5]). US-CERT's alert of 24 April said infected computers had to be cleaned to keep connectivity after 9 July and that Operation Ghost Click had targeted Rove Digital, distributor of TDSS, Alureon, TidServ and TDL4 (Confirmed [4]).

### Microsoft's civil actions

In Operation b71 Microsoft sued John Does 1 to 39 in the Eastern District of New York on 19 March under civil RICO and the Lanham Act, with FS-ISAC and NACHA as co-plaintiffs and Kyrus Tech also taking part, and on 23 March seized command servers in Scranton, Pennsylvania, and Lombard, Illinois, with the US Marshals (Confirmed [12]). The targets were the Zeus, SpyEye and Ice-IX botnets, with more than 13 million suspected infections worldwide and more than 3 million in the United States, and the stated goal was strategic disruption rather than permanent shutdown (Confirmed [12]). Microsoft says the Zeus-family botnets are blamed for nearly half a billion dollars in damages; that is an experts' estimate (Reported [12]). In Operation b70 the Eastern District of Virginia granted an ex parte order on 10 September against Peng Yong, his company and John Does that let Microsoft host the 3322.org domain, which hosted about 500 malware strains on more than 70,000 subdomains; Microsoft found new PCs sold with counterfeit Windows that carried malware through an insecure supply chain, and Nitol performs DDoS (Confirmed [13]).

### Operation Card Shop

The Manhattan US Attorney and the FBI announced on 26 June the end of a two-year undercover carding operation, with 24 arrests, 11 in the United States and 13 abroad in seven countries, more than 30 search warrants and 13 countries involved; the government says it protected over 400,000 potential victims and prevented over USD 205 million in losses (Confirmed that the government says so [32]).

### Reveton and Carberp

The FBI warned on 9 August that Reveton drive-by ransomware locks the screen with a fake FBI violation notice and demands a fine, and said IC3 was inundated with complaints (Confirmed [77]). The FBI later said Citadel malware delivered Reveton and that Microsoft, the FBI and financial partners disrupted Citadel botnets in June 2013 (Confirmed [78]). The ransomware context is in [the ransomware ecosystem](/case-studies/RANSOMWARE_ECOSYSTEM.md) study. ATT&CK's [S0484 Carberp](/mitre/software/S0484.md) is a credential stealer active since at least 2009 whose source leaked in 2013 and became the basis of Carbanak; the 2012 Carberp arrests were not opened (Confirmed [79]).

### Hacktivist charges (summary)

The [Four Books on Cybercrime](/case-studies/CYBERCRIME_FOUR_BOOKS.md) study, Part 3, is the home. On 6 March the Southern District of New York unsealed charges against Ackroyd, Davis, Martyn and O'Cearrbhail for the Fox, Sony Pictures and PBS hacks, and Monsegur's guilty plea of 15 August 2011; Jeremy Hammond of AntiSec had been arrested in Chicago late on 5 March over the December 2011 Stratfor hack, which affected about 860,000 subscriber accounts (Confirmed as charged [6][7]). The conduct is as alleged.

## Part 9: industrial systems

ICS-CERT's alert ICS-ALERT-12-020-01 says Project Basecamp researchers disclosed PLC vulnerabilities at Digital Bond's S4 conference on 19 January without coordinating with vendors or ICS-CERT, covering GE D20, Rockwell ControlLogix and MicroLogix, Schneider Modicon Quantum, Koyo DirectLOGIC and Schweitzer SEL-2032, that exploit modules were released for the GE devices, and that the affected sectors were chemical, energy, water, nuclear and critical manufacturing (Confirmed [82]). ICS-ALERT-12-195-01 says Tridium's Niagara AX building automation framework had a directory traversal flaw and weak credential storage with public proof-of-concept code, that a public report forced ICS-CERT to shorten its release schedule, and that follow-up advisory ICSA-12-228-01 was posted on 15 August; the 13 July date comes from the alert code's day-of-year (Confirmed [83]; date Inferred).

KrebsOnSecurity, relaying a customer letter, reported that Telvent Canada learned on 10 September of a breach in which attackers installed malware and stole project files for its OASyS SCADA product, that Telvent cut remote links to customer systems, and that experts tied the indicators to the Comment Group (Reported [84]). Mandiant's APT1 report attributes the Telvent breach to APT1 by tools and infrastructure (Confirmed as Mandiant's attribution [58]). Flame's two ATT&CK for ICS techniques, T0893 Data from Local System and T0882 Theft of Operational Information, are the only ICS ids the 2012 record supports (Confirmed [22]; that they are the only ones is Inferred). The [ICS attacks and advisories](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md) study carries the later ICS record.

## Part 10: law, policy and standards

### Legislation and policy

The House passed H.R. 3523, the Cyber Intelligence Sharing and Protection Act, 248 to 168 on Roll Call 192 on 26 April (Confirmed [89]). On 2 August the Senate rejected cloture on S. 3414, the Cybersecurity Act of 2012, 52 to 46 on vote 187, where three-fifths was required; a second vote in November was not checked (Confirmed [90]). The European Commission proposed on 25 January to reform the 1995 data protection rules as a Regulation and a Directive, with a single set of rules and a duty to notify serious breaches to the supervisory authority as soon as possible, within 24 hours where feasible, and claimed about EUR 2.3 billion a year in business savings (Confirmed that the Commission says so [87]). On 28 March it proposed a European Cybercrime Centre within Europol in The Hague, focused on organized online fraud, online child sexual exploitation and attacks on critical infrastructure; the centre's opening date was not checked (Confirmed [88]). The ITU convened WCIT-12 in Dubai from 3 to 14 December to review the International Telecommunication Regulations (Confirmed [93]).

### NIST

NIST published SP 800-61 Rev. 2, the Computer Security Incident Handling Guide, in August 2012 (history dated 6 August), superseding Rev. 1 of 2008; it was withdrawn on 3 April 2025 for Rev. 3 (Confirmed [91]). SP 800-30 Rev. 1, the Guide for Conducting Risk Assessments, is dated 17 September, supersedes the 2002 edition and supports SP 800-39 at all three risk tiers (Confirmed [92]). FIPS 180-4, the Secure Hash Standard, is dated 6 March, superseding FIPS 180-3; the 2012 version was withdrawn on 5 August 2015 for an updated FIPS 180-4 (Confirmed [94]). On 2 October NIST announced Keccak as the SHA-3 winner after a five-year competition opened in 2007, chosen over 63 other submissions (Confirmed [95]). SP 800-53 Rev. 4 final is dated 30 April 2013, and the CSRC page lists no 2012 draft, so no 2012 draft date is given here (Confirmed [102]).

### IETF

RFC 6520 (February) defined the TLS and DTLS Heartbeat Extension, the extension whose OpenSSL implementation later held Heartbleed, an event for a later year's chronicle (Confirmed [96]; the link is Inferred). RFC 6698 (August) defined DANE TLSA records, which publish TLS server keys in DNSSEC-protected DNS so clients need not rely only on third-party CAs (Confirmed [97]). RFC 6749 (October) defined OAuth 2.0 and obsoleted RFC 5849, OAuth 1.0 (Confirmed [98]). RFC 6797 (November) defined HTTP Strict Transport Security, through which a site declares that it may be reached only over secure connections (Confirmed [99]).

### MITRE's weakness and attack-pattern catalogs

CWE 2.2 was posted on 15 May and 2.3 on 30 October; the CWE Compatibility program declared its first 13 officially compatible products from five organizations on 28 February and reached 20 by 30 October; and there was no new Top 25 list in 2012, only a pocket guide update on 30 October (Confirmed [100]). CAPEC 1.7 was posted on 25 March with 14 new patterns and 30 brought to Complete status, CAPEC 1.7.1 on 27 April, and a CAPEC Compatibility section was added on 27 February (Confirmed [101]).

## Part 11: the defender view

**Plug-ins needed removing, not only patching.** US-CERT advised disabling Java in browsers, and three Java flaws of 2012 carry KEV's known-ransomware flag (Confirmed [41][55]). [Executable Allowlisting](/mitre/d3fend/executable-allowlisting.md) and the exploit mitigations [Process Segment Execution Prevention](/mitre/d3fend/process-segment-execution-prevention.md) and [Segment Address Offset Randomization](/mitre/d3fend/segment-address-offset-randomization.md) are the library's D3FEND pages that fit; the library links the latter two to T1189 and T1203 (Demonstrated [116]; Inferred for the pairing). [M1021 Restrict Web-Based Content](/mitre/mitigations/M1021.md), [M1042 Disable or Remove Feature or Program](/mitre/mitigations/M1042.md), [M1048 Application Isolation and Sandboxing](/mitre/mitigations/M1048.md) and [M1050 Exploit Protection](/mitre/mitigations/M1050.md) are the ATT&CK mitigations (Inferred).

**Interim workarounds bought days.** Microsoft's Fix it and EMET workaround for CVE-2012-4969 came two to three days before MS12-063, and the MSXML Fix it came before MS12-043 (Confirmed [47][30][31]). [Software Update](/mitre/d3fend/software-update.md) and [M1051 Update Software](/mitre/mitigations/M1051.md) cover the fix itself (Inferred).

**Certificate trust needed its own runbook.** Microsoft untrusted its own intermediates and further non-conforming CAs, rejected short RSA keys, and Adobe revoked a code-signing certificate (Confirmed [23][33][103][51]). [Certificate Analysis](/mitre/d3fend/certificate-analysis.md) and [Certificate Pinning](/mitre/d3fend/certificate-pinning.md) are the matching D3FEND pages, and the library links no countermeasure to T1553.002 or T1588.004 (Demonstrated [116][114]; Inferred for the pairing). HSTS and DANE, both standardized in 2012, are the protocol answers (Confirmed [99][97]; Inferred). [M1045 Code Signing](/mitre/mitigations/M1045.md) and [M1054 Software Configuration](/mitre/mitigations/M1054.md) are the ATT&CK mitigations (Inferred). The [certificate trust incident response reference](/CERTIFICATE_TRUST_INCIDENT_RESPONSE_REFERENCE.md) carries the playbook side (Inferred).

**Destruction needed backups out of reach.** DHS and the FBI advised separate, secure backups in January; Wiper and Shamoon destroyed data and disk structures later in the year (Confirmed [86][19][39]). The library links only [Disk Partitioning](/mitre/d3fend/disk-partitioning.md) to T1561.002 and nothing to T1485 (Demonstrated [116]); [M1053 Data Backup](/mitre/mitigations/M1053.md) is the ATT&CK mitigation (Inferred).

**Volumetric floods needed capacity and filtering upstream.** The bank DDoS reached about 140 Gbps as alleged, and Anonymous used HTTP GET and UDP floods (Confirmed as alleged [57]; Confirmed [2]). The library links [Inbound Traffic Filtering](/mitre/d3fend/inbound-traffic-filtering.md), [Inbound Session Volume Analysis](/mitre/d3fend/inbound-session-volume-analysis.md) and [Network Traffic Filtering](/mitre/d3fend/network-traffic-filtering.md) to T1498.001 and T1499.002 (Demonstrated [116]); [M1037 Filter Network Traffic](/mitre/mitigations/M1037.md) is the ATT&CK mitigation (Inferred).

**Reused passwords opened other companies' doors.** Dropbox's takeovers used passwords stolen elsewhere, and Dropbox added two-factor authentication (Confirmed [35]). [Multi-factor Authentication](/mitre/d3fend/multi-factor-authentication.md) and [Strong Password Policy](/mitre/d3fend/strong-password-policy.md) are the library's D3FEND pages that fit, the library links [Connection Attempt Analysis](/mitre/d3fend/connection-attempt-analysis.md) and [User Geolocation Logon Pattern Analysis](/mitre/d3fend/user-geolocation-logon-pattern-analysis.md) to T1110.004, and [M1032 Multi-factor Authentication](/mitre/mitigations/M1032.md) and [M1027 Password Policies](/mitre/mitigations/M1027.md) are the ATT&CK mitigations (Demonstrated [116]; Inferred for the pairing).

**Watering holes and documents both needed filtering.** Elderwood used compromised sites and malicious files, Madi used slideshows with reversed filenames, and US-CERT warned of compromised CMS sites (Confirmed [46][34][50]). The library links [URL Reputation Analysis](/mitre/d3fend/url-reputation-analysis.md) and [URL Analysis](/mitre/d3fend/url-analysis.md) to T1189, and [Email Filtering](/mitre/d3fend/email-filtering.md), [File Analysis](/mitre/d3fend/file-analysis.md) and [Dynamic Analysis](/mitre/d3fend/dynamic-analysis.md) to T1566.001 (Demonstrated [116]); [M1017 User Training](/mitre/mitigations/M1017.md) is the ATT&CK mitigation (Inferred).

**Removable media still carried state malware.** Flame and Gauss both had USB modules (Confirmed [20][37]). The library links [IO Port Restriction](/mitre/d3fend/io-port-restriction.md) and [Hardware Component Inventory](/mitre/d3fend/hardware-component-inventory.md) to T1091, and [M1034 Limit Hardware Installation](/mitre/mitigations/M1034.md) is the ATT&CK mitigation (Demonstrated [116]; Inferred).

**Incident handling got a federal playbook.** SP 800-61 Rev. 2 and SP 800-30 Rev. 1 arrived in August and September (Confirmed [91][92]). The [incident response reference](/INCIDENT_RESPONSE_REFERENCE.md) and the [GRC and compliance reference](/GRC_COMPLIANCE_REFERENCE.md) cover the process side (Inferred).

## Part 12: MITRE mappings

No 2012 record opened here carries an ATT&CK id; every binding below is a later mapping (Inferred). Every Enterprise binding is either a technique ATT&CK lists for an object it ties to 2012 (S0143 Flame, S0140 Shamoon, G0066 Elderwood, G0006 APT1) or this study's mapping of a behavior a source describes (Inferred). Every id was checked against the library's data files (`data/attack/technique_profiles.jsonl`, `software_to_technique.jsonl`, `group_to_technique.jsonl`, `groups.jsonl`, `software.jsonl`, `campaigns.jsonl`, `technique_to_d3fend.jsonl`, `data/attack/ics/` and `data/weaknesses/`) and against the generated pages under `mitre/` on 12 and 13 November 2026 (Demonstrated [116][117]). Names and tactics are those of ATT&CK v20.0 as the library carries them, including the v20.0 tactics stealth and defense-impairment (Demonstrated [116]).

The Basis column says how strong each tie is, as in the [2016 chronicle](/case-studies/CHRONICLE_2016.md). **Listed** means ATT&CK itself lists the id for the object. **Described** means a primary source describes the behavior and this study assigns the id. **Reported** means only a Reported source describes it. **Inferred** means the mapping rests on this study's reading. Two caveats apply to the Listed rows: Shamoon's ATT&CK record covers Shamoon 1 to 3, and only the two ids that cite the 2012 report are bound; and APT1's record spans years of reporting, and only T1566.002 and T1585.002, which Mandiant's account of the April 2012 phishing describes, are bound as Listed (Confirmed [40][58][61]; Demonstrated [116]).

### ATT&CK Enterprise techniques

| Id | Name (ATT&CK v20.0) | Tactic(s) | Basis | Dated event or report | Sources |
|---|---|---|---|---|---|
| [`T1584.005`](/mitre/techniques/T1584-005.md) | Botnet | resource-development | Inferred | The 2011 to 2013 bank DDoS, as alleged (near-weekly from Sep 2012) | [57] |
| [`T1585.002`](/mitre/techniques/T1585-002.md) | Email Accounts | resource-development | Listed (G0006); Described | APT1's free-webmail account impersonating Mandiant's CEO (18 Apr) | [61][58] |
| [`T1588.004`](/mitre/techniques/T1588-004.md) | Digital Certificates | resource-development | Described | Unauthorized certificates derived from a Microsoft CA (Advisory 2718704, 3 Jun; collision post, 6 Jun) | [23][25][26] |
| [`T1608.004`](/mitre/techniques/T1608-004.md) | Drive-by Target | resource-development | Described | Elderwood's renewed compromise of a website its targets visited (6 Sep); compromised WordPress and Joomla sites hosting content that infected visitors (21 Sep) | [46][50] |
| [`T1189`](/mitre/techniques/T1189.md) | Drive-by Compromise | initial-access | Listed (G0066); Described | Elderwood (6 Sep); Reveton by drive-by download (9 Aug); IE CVE-2012-4969 and Java CVE-2012-4681 exploited (Aug and Sep; match Inferred) | [45][46][77][41][49][111] |
| [`T1190`](/mitre/techniques/T1190.md) | Exploit Public-Facing Application | initial-access | Described | Increased exploitation of WordPress and Joomla (21 Sep); PHP-CGI CVE-2012-1823 and Struts CVE-2012-0391 in KEV (match Inferred) | [50][74][76][55] |
| [`T1195`](/mitre/techniques/T1195.md) | Supply Chain Compromise | initial-access | Described | New PCs sold with counterfeit Windows carrying malware (Nitol, Operation b70, 13 Sep) | [13] |
| [`T1566.001`](/mitre/techniques/T1566-001.md) | Spearphishing Attachment | initial-access | Listed (G0066); Described | Elderwood (6 Sep); Madi's spearphishing slideshows (17 Jul); CVE-2012-0158 targeted attacks (10 Apr; vector Inferred) | [45][34][14] |
| [`T1566.002`](/mitre/techniques/T1566-002.md) | Spearphishing Link | initial-access | Listed (G0066, G0006); Described | Elderwood (6 Sep); APT1's link to a ZIP sent to Mandiant staff (18 Apr) | [45][61][58] |
| [`T1091`](/mitre/techniques/T1091.md) | Replication Through Removable Media | lateral-movement, initial-access | Listed (S0143); Described | Flame (28 May); Gauss's USB module (9 Aug) | [22][20][37] |
| [`T1078`](/mitre/techniques/T1078.md) | Valid Accounts | stealth, persistence, privilege-escalation, initial-access | Described | A stolen password opened a Dropbox employee's account (31 Jul) | [35] |
| [`T1203`](/mitre/techniques/T1203.md) | Exploitation for Client Execution | execution | Listed (G0066); Described; Reported | Elderwood's zero-days (6 Sep); CVE-2012-0158 (Apr), CVE-2012-1889 (Jun), CVE-2012-1535 in a Word document (Aug), CVE-2012-4681 (Aug), CVE-2012-4969 (Sep); Flashback through Java (Mar, per Dr.Web) | [45][46][14][30][38][41][49][16] |
| [`T1204.001`](/mitre/techniques/T1204-001.md) | Malicious Link | execution | Listed (G0066) | Elderwood (6 Sep) | [45] |
| [`T1204.002`](/mitre/techniques/T1204-002.md) | Malicious File | execution | Listed (G0066) | Elderwood (6 Sep) | [45] |
| [`T1136.001`](/mitre/techniques/T1136-001.md) | Local Account | persistence | Listed (S0143) | Flame (28 May) | [22] |
| [`T1547.002`](/mitre/techniques/T1547-002.md) | Authentication Package | persistence, privilege-escalation | Listed (S0143) | Flame (28 May) | [22] |
| [`T1027.002`](/mitre/techniques/T1027-002.md) | Software Packing | stealth | Listed (G0066) | Elderwood (6 Sep) | [45] |
| [`T1027.013`](/mitre/techniques/T1027-013.md) | Encrypted/Encoded File | stealth | Listed (G0066) | Elderwood (6 Sep) | [45] |
| [`T1036.002`](/mitre/techniques/T1036-002.md) | Right-to-Left Override | stealth | Described | Madi's right-to-left-override filenames (17 Jul) | [34] |
| [`T1036.010`](/mitre/techniques/T1036-010.md) | Masquerade Account Name | stealth | Listed (S0143) | Flame (28 May) | [22] |
| [`T1218.011`](/mitre/techniques/T1218-011.md) | Rundll32 | stealth | Listed (S0143) | Flame (28 May) | [22] |
| [`T1553.002`](/mitre/techniques/T1553-002.md) | Code Signing | defense-impairment | Described | Licensing certificates that could sign code as Microsoft (3 and 6 Jun); an Adobe certificate used to sign malicious code (28 Sep); not in S0143's ATT&CK mapping | [25][26][51] |
| [`T1110.004`](/mitre/techniques/T1110-004.md) | Credential Stuffing | credential-access | Described | Passwords stolen from other websites used to sign in to Dropbox accounts (31 Jul) | [35][115] |
| [`T1555.003`](/mitre/techniques/T1555-003.md) | Credentials from Web Browsers | credential-access | Inferred | Gauss takes browser data (9 Aug) | [37] |
| [`T1518.001`](/mitre/techniques/T1518-001.md) | Security Software Discovery | discovery | Listed (S0143) | Flame (28 May) | [22] |
| [`T1210`](/mitre/techniques/T1210.md) | Exploitation of Remote Services | lateral-movement | Listed (S0143) | Flame's spread through MS10-061 (28 May) | [22][20] |
| [`T1123`](/mitre/techniques/T1123.md) | Audio Capture | collection | Listed (S0143) | Flame (28 May) | [22][20] |
| [`T1113`](/mitre/techniques/T1113.md) | Screen Capture | collection | Listed (S0143) | Flame (28 May) | [22][20] |
| [`T1114.002`](/mitre/techniques/T1114-002.md) | Remote Email Collection | collection | Listed (G0006); 2012 binding Inferred | USW e-mails (31 Jan) and SolarWorld executives' e-mails (3 May), as alleged | [61][60] |
| [`T1105`](/mitre/techniques/T1105.md) | Ingress Tool Transfer | command-and-control | Listed (G0066) | Elderwood (6 Sep) | [45] |
| [`T1011.001`](/mitre/techniques/T1011-001.md) | Exfiltration Over Bluetooth | exfiltration | Listed (S0143) | Flame (28 May) | [22] |
| [`T1485`](/mitre/techniques/T1485.md) | Data Destruction | impact | Listed (S0140, 2012 source) | Shamoon (Kaspersky, 16 Aug; Symantec, 16 Aug, as ATT&CK cites) | [40][39] |
| [`T1561.002`](/mitre/techniques/T1561-002.md) | Disk Structure Wipe | impact | Listed (S0140, 2012 source) | Shamoon overwrites the master boot record (16 Aug) | [40][39] |
| [`T1498`](/mitre/techniques/T1498.md) | Network Denial of Service | impact | Described | The bank DDoS, as alleged (sporadic from Dec 2011, near-weekly from Sep 2012); the AT&T attacks (Aug, as alleged); Nitol performs DDoS (13 Sep) | [57][56][13] |
| [`T1498.001`](/mitre/techniques/T1498-001.md) | Direct Network Flood | impact | Described | UDP flood against government and entertainment sites (TA12-024A, 24 Jan) | [2] |
| [`T1499.002`](/mitre/techniques/T1499-002.md) | Service Exhaustion Flood | impact | Described | HTTP GET flood against the same sites (TA12-024A, 24 Jan) | [2] |

Left out on purpose: the 22 Shamoon techniques that cite 2016 or 2018 sources, among them T1486, T1529, T1021.002, T1053.005, T1570 and T1078.002 [40]; T1557 for CRIME and T1210 for CVE-2012-0002, which the record pairs with those flaws but which have no exploitation in NVD or KEV [107][105][55]; any technique for Global Payments, LinkedIn and Barnes & Noble, whose filings describe no method [8][28][54]; any technique for Wiper, which no sample documents [19]; any technique for Megaupload, Card Shop, DNSChanger and the Zeus-family takedowns, whose primaries describe crimes and remedies, not intrusion steps [1][32][3][12]; the Telvent breach, which rests on a Reported source [84]; Red October, which has no ATT&CK object [63][116], and Epic Turla, whose 2012 start is inferred and whose Turla mapping ([G0010](/mitre/groups/G0010.md)) lives in the Russia home study [64][115]; and the techniques of the groups first dated to 2012 and of Operation Dust Storm, none tied to a dated 2012 event in the record [67][110].

### ATT&CK for ICS

The library has no generated pages for ICS techniques, so the ids are plain text; names and tactics are those in `data/attack/ics/` (Demonstrated [116][117]). No ICS layer is saved for this chronicle.

| Id | Name (ATT&CK for ICS v20.0) | Tactic(s) | Object | Basis | Dated event or report | Sources |
|---|---|---|---|---|---|---|
| T0893 | Data from Local System | collection | S0143 Flame | Listed | Flame (28 May) | [22] |
| T0882 | Theft of Operational Information | impact | S0143 Flame | Listed | Flame (28 May) | [22] |

Project Basecamp, the Tridium alert and the Telvent breach are not bound: the first two are disclosures, not attacks, and Telvent rests on a Reported source and a vendor attribution (Confirmed [82][83]; Reported [84]; Inferred).

### ATT&CK groups, software and campaigns

| Object | Id | Binding | Sources |
|---|---|---|---|
| Flame | [S0143](/mitre/software/S0143.md) | Bound: published 28 May 2012; all ten Enterprise techniques in the layer, two ICS techniques in the table above | [22][20] |
| Shamoon | [S0140](/mitre/software/S0140.md) | Bound with a caveat: first used 2012; two of 24 techniques, the ones citing the 2012 report | [40][39] |
| Elderwood | [G0066](/mitre/groups/G0066.md) | Bound: "The Elderwood Project", 6 Sep 2012; all nine techniques in the layer | [45][46] |
| Hydraq, PoisonIvy, Briba, Naid, Wiarp, Vasport, Pasam, Nerex, Linfo | [S0203](/mitre/software/S0203.md), [S0012](/mitre/software/S0012.md), [S0204](/mitre/software/S0204.md), [S0205](/mitre/software/S0205.md), [S0206](/mitre/software/S0206.md), [S0207](/mitre/software/S0207.md), [S0208](/mitre/software/S0208.md), [S0210](/mitre/software/S0210.md), [S0211](/mitre/software/S0211.md) | Context: ATT&CK lists them for G0066; their own techniques are not bound | [45][116] |
| APT1 | [G0006](/mitre/groups/G0006.md) | Bound with a caveat: two techniques as Listed and one Inferred, from Mandiant's 2012 account and the 2014 indictment | [61][58][60] |
| Carberp | [S0484](/mitre/software/S0484.md) | Context only: active since at least 2009; the 2012 arrests not opened | [79] |
| Molerats, Stealth Falcon, PROMETHIUM, APT37, Dark Caracal, GALLIUM, Kimsuky, APT41, Mofang, Sidewinder, Volatile Cedar, Mustang Panda, Daggerfly | [G0021](/mitre/groups/G0021.md), [G0038](/mitre/groups/G0038.md), [G0056](/mitre/groups/G0056.md), [G0067](/mitre/groups/G0067.md), [G0070](/mitre/groups/G0070.md), [G0093](/mitre/groups/G0093.md), [G0094](/mitre/groups/G0094.md), [G0096](/mitre/groups/G0096.md), [G0103](/mitre/groups/G0103.md), [G0121](/mitre/groups/G0121.md), [G0123](/mitre/groups/G0123.md), [G0129](/mitre/groups/G0129.md), [G1034](/mitre/groups/G1034.md) | Context only: ATT&CK dates first activity to 2012 | [67][109] |
| Tonto Team | [G0131](/mitre/groups/G0131.md) | Context only: Heartbeat Campaign 2009 to 2012 | [67] |
| Dragonfly | [G0035](/mitre/groups/G0035.md) | Context only: active since at least 2010; no 2012 date | [65][116] |
| Operation Dust Storm | [C0016](/mitre/campaigns/C0016.md) | Context only: January 2010 to February 2016 | [110] |
| Cleaver | [G0003](/mitre/groups/G0003.md) | Not dated to 2012: no active dates on the page | [68] |
| Wiper (ATT&CK) | [S0041](/mitre/software/S0041.md) | Not bound: a 2013 Korean object, not the 2012 Wiper that hit Iran | [19][116] |

The library's ATT&CK data has no object for Gauss, Madi, Red October, the Wiper that hit Iran, the Cutting Sword of Justice, the ITSecTeam and Mersad campaign, the classic Zeus, SpyEye or Ice-IX botnets, Citadel, Reveton, Flashback, Nitol or DNSChanger (Demonstrated [116]).

### CWE and CAPEC

The CWE column names the source of each id. Names are those in the library's CWE and CAPEC data, and every CAPEC listed has a page under `/mitre/capec/` (Demonstrated [116][117]). The library has no per-CWE generated pages, so CWE ids are plain text; the [CWE reference](/CWE_REFERENCE.md) is the library's entry point.

| CWE | Weakness (library name) | Basis | 2012 record | CAPEC |
|---|---|---|---|---|
| CWE-416 | Use After Free | NVD [49][73]; name [113] | IE CVE-2012-4969 (Sep); IE CVE-2012-4792 (Dec) | None (the library relates none to these flaws) |
| CWE-94 | Improper Control of Generation of Code | NVD; CVE record (CISA ADP) | Office common controls CVE-2012-0158 (Apr); RDP CVE-2012-0002 (Mar); Flash CVE-2012-1535 (Aug, CVE record) | None assigned |
| CWE-787 | Out-of-bounds Write | NVD; CVE record (CISA ADP) | MSXML CVE-2012-1889 (Jun); Flash CVE-2012-0754 (Feb) | None assigned |
| CWE-284 | Improper Access Control | NVD | Java CVE-2012-4681 (Aug); Java CVE-2012-1723 (Jun) | None assigned |
| CWE-843 | Access of Resource Using Incompatible Type | NVD | Java CVE-2012-0507 (Jun) | None assigned |
| CWE-77 | Improper Neutralization of Special Elements used in a Command | NVD | PHP-CGI CVE-2012-1823 (May) | None assigned |
| CWE-20 | Improper Input Validation | NVD; CVE record (CISA ADP) | Flash CVE-2012-1535 (Aug) | None assigned |
| CWE-310 | (a category, as NVD lists it; not in the library's CWE data) | NVD | CRIME, CVE-2012-4929 (Sep) | None |
| CWE-327, CWE-295, CWE-290 | (as CAPEC-459 relates them) | Study's pairing | Advisory 2718704 and the collision post (Jun) (Inferred) | [CAPEC-459](/mitre/capec/CAPEC-459.md) Creating a Rogue Certification Authority Certificate, the closest pattern to the licensing-certificate forgery; the MSRC post describes the collision, the advisory does not, so the binding is Inferred [112][26] |
| none bound | (spearphishing) | Library data | Elderwood; Madi; APT1's message to Mandiant | [CAPEC-163](/mitre/capec/CAPEC-163.md) Spear Phishing (on T1566.001 and T1566.002) |
| none bound | (code signing) | Library data | Licensing certificates; the Adobe certificate | [CAPEC-68](/mitre/capec/CAPEC-68.md) Subvert Code-signing Facilities; [CAPEC-206](/mitre/capec/CAPEC-206.md) Signing Malicious Code; [CAPEC-473](/mitre/capec/CAPEC-473.md) Signature Spoof (on T1553.002) |
| none bound | (removable media) | Library data | Flame; Gauss | [CAPEC-457](/mitre/capec/CAPEC-457.md) USB Memory Attacks (on T1091) |
| none bound | (Flame's collection) | Library data | Flame | [CAPEC-634](/mitre/capec/CAPEC-634.md) Probe Audio and Video Peripherals (on T1123); [CAPEC-648](/mitre/capec/CAPEC-648.md) Collect Data from Screen Capture (on T1113); [CAPEC-581](/mitre/capec/CAPEC-581.md) Security Software Footprinting (on T1518.001) |
| none bound | (credentials) | Library data | Dropbox; APT1's e-mail theft | [CAPEC-600](/mitre/capec/CAPEC-600.md) Credential Stuffing (on T1110.004); [CAPEC-560](/mitre/capec/CAPEC-560.md) Use of Known Domain Credentials (on T1078); [CAPEC-555](/mitre/capec/CAPEC-555.md) Remote Services with Stolen Credentials (on T1114.002) |
| none bound | (flooding) | Library data; study's pairing | TA12-024A | [CAPEC-488](/mitre/capec/CAPEC-488.md) HTTP Flood (on T1499.002); [CAPEC-125](/mitre/capec/CAPEC-125.md) Flooding (on T1498.001); [CAPEC-486](/mitre/capec/CAPEC-486.md) UDP Flood (study's pairing for the UDP flood; the library does not relate it to T1498.001) |
| none bound | (supply chain) | Library data | Nitol's counterfeit-Windows PCs | [CAPEC-438](/mitre/capec/CAPEC-438.md) Modification During Manufacture; [CAPEC-439](/mitre/capec/CAPEC-439.md) Manipulation During Distribution (on T1195) |

### D3FEND countermeasures

The technique-to-countermeasure links come from the library's D3FEND data; pairing them with the 2012 record is this study's reading (Demonstrated [116]; Inferred). Every page exists under `/mitre/d3fend/` (Demonstrated [117]).

| Technique or event from the record | D3FEND countermeasures (D3FEND tactic) | 2012 analogue |
|---|---|---|
| T1189 | [URL Reputation Analysis](/mitre/d3fend/url-reputation-analysis.md) (Detect); [URL Analysis](/mitre/d3fend/url-analysis.md) (Detect); [Network Traffic Filtering](/mitre/d3fend/network-traffic-filtering.md) (Isolate); [Process Segment Execution Prevention](/mitre/d3fend/process-segment-execution-prevention.md) (Harden); [Segment Address Offset Randomization](/mitre/d3fend/segment-address-offset-randomization.md) (Harden) | Elderwood's watering holes [46]; Reveton [77]; compromised CMS sites [50] |
| T1203 | [Memory Boundary Tracking](/mitre/d3fend/memory-boundary-tracking.md) (Detect); [Process Code Segment Verification](/mitre/d3fend/process-code-segment-verification.md) (Detect); [Shadow Stack Comparisons](/mitre/d3fend/shadow-stack-comparisons.md) (Detect); [Stack Frame Canary Validation](/mitre/d3fend/stack-frame-canary-validation.md) (Harden); plus the two Harden pages above | The exploited IE, Java, Office, MSXML and Flash flaws [14][30][38][41][49]; no 2012 source opened here names these controls (Inferred) |
| T1566.001, T1566.002 | [Email Filtering](/mitre/d3fend/email-filtering.md) (Isolate); [File Analysis](/mitre/d3fend/file-analysis.md) (Detect); [Dynamic Analysis](/mitre/d3fend/dynamic-analysis.md) (Detect); [Emulated File Analysis](/mitre/d3fend/emulated-file-analysis.md) (Detect) | Elderwood [46]; Madi [34]; APT1's message to Mandiant [58] |
| T1218.011, T1204.002 | [Executable Allowlisting](/mitre/d3fend/executable-allowlisting.md) (Isolate); [Executable Denylisting](/mitre/d3fend/executable-denylisting.md) (Isolate); [Process Spawn Analysis](/mitre/d3fend/process-spawn-analysis.md) (Detect) | Flame [22]; Elderwood [45] |
| T1091, T1123 | [IO Port Restriction](/mitre/d3fend/io-port-restriction.md) (Isolate); [Hardware Component Inventory](/mitre/d3fend/hardware-component-inventory.md) (Model); [Input Device Analysis](/mitre/d3fend/input-device-analysis.md) (Detect, on T1123); the library also links Radiation Hardening | Flame's USB and audio modules [20]; Gauss's USB module [37] |
| T1113, T1518.001 | [System Call Analysis](/mitre/d3fend/system-call-analysis.md) (Detect); [System Call Filtering](/mitre/d3fend/system-call-filtering.md) (Isolate) | Flame [20] |
| T1555.003 | [File Encryption](/mitre/d3fend/file-encryption.md) (Harden); [Local File Permissions](/mitre/d3fend/local-file-permissions.md) (Isolate); [Restore File](/mitre/d3fend/restore-file.md) (Restore) | Gauss's browser data theft [37] (Inferred) |
| T1110.004, T1078 | [Connection Attempt Analysis](/mitre/d3fend/connection-attempt-analysis.md) (Detect); [User Geolocation Logon Pattern Analysis](/mitre/d3fend/user-geolocation-logon-pattern-analysis.md) (Detect); [Account Locking](/mitre/d3fend/account-locking.md) (Evict); [Multi-factor Authentication](/mitre/d3fend/multi-factor-authentication.md) and [Strong Password Policy](/mitre/d3fend/strong-password-policy.md) (study's pairing) | Dropbox [35] |
| T1190 | [Inbound Traffic Filtering](/mitre/d3fend/inbound-traffic-filtering.md) (Isolate); [Database Query String Analysis](/mitre/d3fend/database-query-string-analysis.md) (Detect); [Client-server Payload Profiling](/mitre/d3fend/client-server-payload-profiling.md) (Detect) | WordPress and Joomla exploitation [50]; PHP-CGI and Struts [74][76] |
| T1498.001, T1499.002 | [Inbound Traffic Filtering](/mitre/d3fend/inbound-traffic-filtering.md) (Isolate); [Inbound Session Volume Analysis](/mitre/d3fend/inbound-session-volume-analysis.md) (Detect); [Network Traffic Filtering](/mitre/d3fend/network-traffic-filtering.md) (Isolate) | TA12-024A [2]; the bank DDoS [57] (Inferred for T1498) |
| T1561.002 | [Disk Partitioning](/mitre/d3fend/disk-partitioning.md) (Evict), the only link in the library | Shamoon [39] |
| T1210 | [Connection Attempt Analysis](/mitre/d3fend/connection-attempt-analysis.md) (Detect); [Remote Terminal Session Detection](/mitre/d3fend/remote-terminal-session-detection.md) (Detect) | Flame's MS10-061 spreading [20] |
| T1588.004, T1553.002 (certificate abuse) | [Certificate Analysis](/mitre/d3fend/certificate-analysis.md) and [Certificate Pinning](/mitre/d3fend/certificate-pinning.md) [114] (study's pairing; the library links no countermeasure to either technique) | Advisory 2718704 [23]; Advisory 2661254 [103]; the Adobe certificate [51] (Inferred) |
| Patching the year's flaws | [Software Update](/mitre/d3fend/software-update.md) (study's pairing) | MS12-027, MS12-043, MS12-063, the Java updates, PHP 5.3.13 and 5.4.3 [14][31][48][17][43][75] |

The library links T1485, T1498, T1529, T1553.002, T1584.005, T1585.002, T1588.004, T1608.004, T1036.002, T1036.010, T1011.001, T1027.013 and T1195 to no D3FEND countermeasure (Demonstrated [116]). ATT&CK mitigation pages exist for [M1051 Update Software](/mitre/mitigations/M1051.md), [M1050 Exploit Protection](/mitre/mitigations/M1050.md), [M1048 Application Isolation and Sandboxing](/mitre/mitigations/M1048.md), [M1021 Restrict Web-Based Content](/mitre/mitigations/M1021.md), [M1042 Disable or Remove Feature or Program](/mitre/mitigations/M1042.md), [M1017 User Training](/mitre/mitigations/M1017.md), [M1032 Multi-factor Authentication](/mitre/mitigations/M1032.md), [M1027 Password Policies](/mitre/mitigations/M1027.md), [M1037 Filter Network Traffic](/mitre/mitigations/M1037.md), [M1034 Limit Hardware Installation](/mitre/mitigations/M1034.md), [M1053 Data Backup](/mitre/mitigations/M1053.md), [M1045 Code Signing](/mitre/mitigations/M1045.md), [M1054 Software Configuration](/mitre/mitigations/M1054.md) and [M1040 Behavior Prevention on Endpoint](/mitre/mitigations/M1040.md) (Demonstrated [117]). TA12-240A's advice to disable Java in browsers maps most closely to M1042 and M1021; Advisory 2757760's EMET workaround to M1050; Dropbox's two-factor authentication to M1032; and the certificate untrust updates to M1054 (Inferred [41][47][35][23]).

### Navigator layer

The study's Enterprise techniques are saved as one ATT&CK Navigator layer pinned to ATT&CK v20, [navigator/library-layers/chronicle-2012.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/chronicle-2012.json), in the format of the existing chronicle layers: domain enterprise-attack, described as a curated case-study layer and not an official MITRE mapping (Demonstrated [118]). It lists the 36 techniques in the Enterprise table under each tactic they carry in v20.0, 41 technique-tactic entries in all, and is listed on [the Navigator layers page](/navigator/index.md). The ICS techniques are not in it. Scores show the basis, not severity, in the house scale set by the 2016 chronicle: 100 where an ATT&CK object prints the id, 70 where a primary source describes the behavior and this study assigns the id, 50 where only a Reported source supports it, and 40 for an Inferred mapping (Demonstrated [118]). The 22 techniques listed for S0143, S0140, G0066 or, for T1585.002, G0006 score 100, with a comment noting that Flame's come from ATT&CK's software record, that Shamoon's two cite the 2012 report and that Elderwood's come from ATT&CK's group record; T1588.004, T1608.004, T1190, T1195, T1078, T1036.002, T1553.002, T1110.004, T1498, T1498.001 and T1499.002 score 70; T1584.005, T1555.003 and T1114.002 score 40. No technique scores 50. Each entry's comment names the source numbers in the Sources table below.

## Cross-cutting themes

**Trust infrastructure was both attacked and rebuilt.** A forged Microsoft licensing certificate signed code, an Adobe code-signing certificate signed malware, and in the same year the IETF standardized HSTS and DANE, Windows refused short RSA keys and NIST published FIPS 180-4 and chose SHA-3 (Confirmed [26][51][99][97][103][94][95]; Inferred for the reading).

**The client was the front door.** The record's exploited flaws sit in Java, Internet Explorer, Office's common controls, XML Core Services and Flash, delivered by drive-by pages, watering holes and documents (Confirmed [14][30][38][41][49][46]; Inferred).

**Espionage and destruction surfaced together.** Flame and Gauss collected, while Wiper and Shamoon destroyed, and all four were described in public between May and August (Confirmed [20][37][19][39]).

**Attribution lagged by years.** The bank DDoS was charged in 2016, the PLA thefts in 2014, APT1 named in 2013 and OPM's July 2012 access found in 2015 (Confirmed [56][59][58][81]).

**Breaches became filings and court cases.** Global Payments, LinkedIn, PNC, Capital One and Barnes & Noble described incidents in SEC filings, and the FTC took Wyndham to court (Confirmed [8][28][52][53][54][80]).

**Takedowns kept going to court.** Megaupload, the DNSChanger servers, the Zeus-family servers and Nitol's domain were each handled by a court order (Confirmed [1][3][12][13]).

**Legislatures moved slowly.** The House passed an information-sharing bill, the Senate's broader cybersecurity bill failed cloture, and the European Commission proposed breach notification and a cybercrime centre (Confirmed [89][90][87][88]).

### What is overstated and what is understated

This section is the study's reading of the record (Inferred).

- **Overstated: that Advisory 2718704 names Flame.** It does not, nor does the US-CERT alert; the link comes from Microsoft's MSRC blog posts, which describe certificates that could sign code as Microsoft [23][24][25][26].
- **Overstated: "Shamoon hit Saudi Aramco" as a 2012 finding.** Kaspersky's 2012 post and ATT&CK name no victim; the home study names Saudi Aramco and RasGas only from Kaspersky's March 2017 report, and the 30,000-systems figure from a later Unit 42 recap [39][40][115].
- **Overstated: Shamoon's 2012 technique list.** ATT&CK's S0140 lists 24 techniques across three waves; only two cite the 2012 report [40].
- **Overstated: Iranian attribution of the 2012 wipers.** Kaspersky gives none for Wiper or Shamoon, and ATT&CK's Iranian attribution names a group known as the Cutting Sword of Justice and gives no government finding [19][39][40].
- **Overstated: the dollar figures.** Megaupload's USD 500 million harm and Card Shop's USD 205 million prevented losses are government allegations or estimates, and the Zeus "nearly half a billion" is what unnamed experts believe; Global Payments' USD 84.4 million is the only booked figure here [1][32][12][11].
- **Overstated: the infection counts.** Flashback's 550,000, Zeus's 13 million and Gauss's 2,500 come from each reporting vendor's own data, not audited tallies [16][12][37].
- **Overstated: Gauss as a "nation-state" Trojan.** That rests on Kaspersky's code-kinship judgment [37].
- **Overstated: CRIME.** It drew attention, but NVD records no exploitation and it is not in KEV [107][55].
- **Overstated: the precision of ids on 2012 events.** No 2012 event had a contemporaneous ATT&CK mapping, the Flame and Shamoon objects were created in 2017, and every technique id here comes from a later record or this study's reasoning [22][40].
- **Understated: dwell and delay.** OPM's July 2012 first access was found in 2015, Dropbox's 2012 credential set surfaced in 2016, and Wyndham's 2008 to 2009 breaches reached court in 2012 [81][115][80].
- **Understated: the long tail of 2012 flaws.** CVE-2012-0158 is in KEV with known ransomware use and later groups still exploit it, and KEV added CVE-2012-4792 in 2024 [55][115].
- **Understated: industrial exposure.** Basecamp and Tridium were uncoordinated or forced disclosures with exploit or proof-of-concept code in the same year a SCADA vendor was reportedly breached [82][83][84].
- **Understated: routine standards work.** 5,351 CVE records were published, CWE 2.2 and 2.3 and the first CWE-compatible products appeared, CAPEC 1.7 shipped, and a key-length change broke private PKIs that still used short keys [108][100][101][103].
- **Understated: the policy split.** The broader US Senate bill failed in August while the House sharing bill passed in April, and the EU proposed breach notification and a cybercrime centre the same spring [90][89][87][88].

### Discrepancies in the record

- **Flame's first use.** Kaspersky's Q&A gives use since at least August 2010 and presence in the wild by February or March 2010; CrySyS says possibly five to eight years or more; ATT&CK says since at least 2010 [20][21][22].
- **Flame and Stuxnet.** Kaspersky's 28 May Q&A found no major code similarity to Stuxnet or Duqu; on 11 June it reported a proto-Flame module in the 2009 Stuxnet's resource 207 [20][27].
- **Flame's size.** Kaspersky gives about 20 MB fully deployed and about 20 times larger than Stuxnet [20].
- **How many Microsoft CAs.** Advisory 2718704 lists two Intermediate PCA certificates and one Registration Authority CA, three in all, and MSRC says the whole Terminal Server licensing hierarchy was invalidated [23][26].
- **Gauss's infection count.** Kaspersky gives about 2,500 PCs in 25 countries by 31 July, 2,500 or more recorded, and an estimate of tens of thousands [37][36].
- **Wiper's dates.** Kaspersky puts most incidents between 21 and 30 April and says attacks ran until late April, with similar incidents from December 2011 [19].
- **Global Payments' count.** The 1 April update says fewer than 1,500,000 card numbers may have been exported; the 12 June update says exports did not exceed 1,500,000 [9][10].
- **CVE-2012-1535's CWE.** NVD lists CWE-20; the CVE record's CISA ADP container lists CWE-94 and CWE-20, and the CNA problem type is n/a [38][62].
- **CVE-2012-4681's CWE.** NVD lists CWE-284 and NVD-CWE-Other [44].
- **Flashback's fix date.** Apple's page carries no date; Dr.Web dates Apple's fix to 3 April; US-CERT's alert is of 16 April [17][16][15].
- **Operation b71's parties.** Microsoft names FS-ISAC and NACHA as co-plaintiffs, and Kyrus Tech also took part; the legal bases named are civil RICO and the Lanham Act [12].
- **The Iran indictment's date.** The FBI gives the indictment date as 21 January 2016; the 2016 chronicle records the unsealing on 24 March 2016 [56][115].
- **MS12-063's status.** It was released on a Friday outside the monthly cycle, but the bulletin does not call itself out of band [48].
- **The Tridium alert's date.** The alert code, 12-195, dates it to 13 July (Inferred); the follow-up advisory was posted on 15 August [83].
- **The Elderwood paper's copy.** Symantec's own URL is gone; the text was read from an Internet Archive copy [46].

## Sources

Every external source was opened on 12 or 13 November 2026, and the library data checks were run on the same days, as the Opened column shows. All are checked as of 13 November 2026. Grade is the source's evidence grade as used in this study. Addresses shown as code rather than as links refuse automated link checkers (the NVD API queries, the ten sec.gov addresses of the Global Payments, LinkedIn, PNC, Capital One and Barnes & Noble filings and the ftc.gov Wyndham release); copy them into a browser to open them.

| # | Source | URL | Opened | Grade |
|---|---|---|---|---|
| 1 | FBI and Justice Department, Justice Department charges leaders of Megaupload with widespread online copyright infringement, 19 Jan 2012 (FBI archive) | https://archives.fbi.gov/archives/news/pressrel/press-releases/justice-department-charges-leaders-of-megaupload-with-widespread-online-copyright-infringement | 2026-11-12; 2026-11-13 | Confirmed (as charged; the dollar figures are allegations) |
| 2 | US-CERT (CISA archive), TA12-024A, Anonymous DDoS Activity, 24 Jan 2012 (revised 26 Jan and 23 Apr) | https://www.cisa.gov/news-events/alerts/2012/01/24/anonymous-ddos-activity | 2026-11-12; 2026-11-13 | Confirmed |
| 3 | US-CERT (CISA archive), DNSChanger Malware, 23 Feb 2012 (updated) | https://www.cisa.gov/news-events/alerts/2012/02/23/dnschanger-malware | 2026-11-12; 2026-11-13 | Confirmed |
| 4 | US-CERT (CISA archive), DNSChanger Malware, 24 Apr 2012 | https://www.cisa.gov/news-events/alerts/2012/04/24/dnschanger-malware | 2026-11-13 | Confirmed |
| 5 | FBI, International cyber ring that infected millions of computers dismantled (Operation Ghost Click, updated 12 Mar 2012) | https://www.fbi.gov/news/stories/international-cyber-ring-that-infected-millions-of-computers-dismantled | 2026-11-12 | Confirmed |
| 6 | FBI New York, Six hackers in the United States and abroad charged for crimes affecting over one million victims, 6 Mar 2012 | https://archives.fbi.gov/archives/newyork/press-releases/2012/six-hackers-in-the-united-states-and-abroad-charged-for-crimes-affecting-over-one-million-victims | 2026-11-12; 2026-11-13 | Confirmed (that the charges and the plea were made); the conduct is alleged |
| 7 | US Attorney, SDNY, press release on the LulzSec and AntiSec charges, 6 Mar 2012 (archive) | https://www.justice.gov/archive/usao/nys/pressreleases/March12/ackroyd.html | 2026-11-12 | Confirmed (as charged) |
| 8 | Global Payments, Form 8-K and press release of 30 Mar 2012 (SEC EDGAR) | `https://www.sec.gov/Archives/edgar/data/1123360/000112336012000019/march302012.htm` ; `https://www.sec.gov/Archives/edgar/data/1123360/000112336012000019/0001123360-12-000019-index.htm` | 2026-11-12; 2026-11-13 | Confirmed (the company's account) |
| 9 | Global Payments, press release of 1 Apr 2012 (SEC EDGAR) | `https://www.sec.gov/Archives/edgar/data/1123360/000112336012000025/april12012pressrelease.htm` | 2026-11-12; 2026-11-13 | Confirmed (the company's account) |
| 10 | Global Payments, press release of 12 Jun 2012 (SEC EDGAR) | `https://www.sec.gov/Archives/edgar/data/1123360/000112336012000031/pressrelease061212finalaso.htm` | 2026-11-12; 2026-11-13 | Confirmed (the company's account) |
| 11 | Global Payments, Form 8-K Exhibit 99.1, fiscal 2012 results, 26 Jul 2012 (SEC EDGAR) | `https://www.sec.gov/Archives/edgar/data/1123360/000119312512316921/d386170dex991.htm` | 2026-11-12; 2026-11-13 | Confirmed |
| 12 | Microsoft, Microsoft and financial services industry leaders target cybercriminal operations from Zeus botnets, 25 Mar 2012 | https://blogs.microsoft.com/blog/2012/03/25/microsoft-and-financial-services-industry-leaders-target-cybercriminal-operations-from-zeus-botnets/ | 2026-11-12; 2026-11-13 | Confirmed (the case and seizures); Reported (the damage estimate) |
| 13 | Microsoft, Microsoft disrupts the emerging Nitol botnet being spread through an unsecure supply chain, 13 Sep 2012 | https://blogs.microsoft.com/blog/2012/09/13/microsoft-disrupts-the-emerging-nitol-botnet-being-spread-through-an-unsecure-supply-chain/ | 2026-11-12 | Confirmed |
| 14 | Microsoft Security Bulletin MS12-027, 10 Apr 2012 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-027 | 2026-11-12; 2026-11-13 | Confirmed |
| 15 | US-CERT (CISA archive), Apple Releases Flashback Malware Security Updates, 16 Apr 2012 (updated 14 May) | https://www.cisa.gov/news-events/alerts/2012/04/16/apple-releases-flashback-malware-security-updates | 2026-11-13 | Confirmed |
| 16 | Doctor Web, news on the BackDoor.Flashback botnet, 4 Apr 2012 | https://news.drweb.com/show/?i=2341&lng=en | 2026-11-12 | Reported (the vendor's counts and dates) |
| 17 | Apple, HT5228, About the security content of Java for OS X Lion 2012-002 and Java for Mac OS X 10.6 Update 7 | https://support.apple.com/kb/HT5228 | 2026-11-12 | Confirmed |
| 18 | NVD, CVE-2012-0507 and CVE-2012-1723 (API records) | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2012-0507` ; `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2012-1723` | 2026-11-12 | Confirmed |
| 19 | Kaspersky (Securelist), What was that Wiper thing?, 29 Aug 2012 | https://securelist.com/what-was-that-wiper-thing-48/34088/ | 2026-11-12; 2026-11-13 | Confirmed (the vendor's findings) |
| 20 | Kaspersky (Securelist), The Flame: Questions and Answers, 28 May 2012 | https://securelist.com/the-flame-questions-and-answers/34344/ | 2026-11-12; 2026-11-13 | Confirmed (the vendor's findings); Reported (its nation-state judgment) |
| 21 | CrySyS Lab, sKyWIper: A Complex Malware for Targeted Attacks, v1.05, 31 May 2012 | https://static.crysys.hu/publications/files/skywiper.pdf | 2026-11-13 | Confirmed (the researchers' findings) |
| 22 | MITRE ATT&CK, S0143 Flame | https://attack.mitre.org/software/S0143/ | 2026-11-12; 2026-11-13 | Confirmed |
| 23 | Microsoft Security Advisory 2718704, Unauthorized Digital Certificates Could Allow Spoofing, 3 Jun 2012 (revised 13 Jun) | https://learn.microsoft.com/en-us/security-updates/securityadvisories/2012/2718704 | 2026-11-12; 2026-11-13 | Confirmed |
| 24 | US-CERT (CISA archive), Unauthorized Microsoft Digital Certificates, 4 Jun 2012 | https://www.cisa.gov/news-events/alerts/2012/06/04/unauthorized-microsoft-digital-certificates | 2026-11-13 | Confirmed |
| 25 | MSRC blog, Microsoft releases Security Advisory 2718704, 3 Jun 2012 | https://www.microsoft.com/en-us/msrc/blog/2012/06/microsoft-releases-security-advisory-2718704 | 2026-11-12 | Confirmed |
| 26 | MSRC blog, Flame malware collision attack explained, 6 Jun 2012 | https://www.microsoft.com/en-us/msrc/blog/2012/06/flame-malware-collision-attack-explained | 2026-11-12 | Confirmed |
| 27 | Kaspersky (Securelist), Back to Stuxnet: the missing link, 11 Jun 2012 | https://securelist.com/back-to-stuxnet-the-missing-link/33328/ | 2026-11-12 | Reported (the vendor's kinship analysis) |
| 28 | LinkedIn, Form 10-K for 2012, filed 19 Feb 2013 (SEC EDGAR) | `https://www.sec.gov/Archives/edgar/data/1271024/000127102413000010/lnkd12312012-10kdoc.htm` | 2026-11-13 | Confirmed |
| 29 | LinkedIn, Form 10-Q for Q2 2012 (SEC EDGAR) | `https://www.sec.gov/Archives/edgar/data/1271024/000119312512335359/d351638d10q.htm` | 2026-11-12 | Confirmed |
| 30 | US-CERT (CISA archive), Microsoft XML Core Services Attack Activity, 22 Jun 2012 | https://www.cisa.gov/news-events/alerts/2012/06/22/microsoft-xml-core-services-attack-activity | 2026-11-13 | Confirmed |
| 31 | Microsoft Security Bulletin MS12-043, 10 Jul 2012 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-043 | 2026-11-12 | Confirmed |
| 32 | FBI New York, Manhattan US Attorney and FBI announce 24 arrests in eight countries as part of international cyber crime takedown, 26 Jun 2012 | https://archives.fbi.gov/archives/newyork/press-releases/2012/manhattan-u.s.-attorney-and-fbi-assistant-director-in-charge-announce-24-arrests-in-eight-countries-as-part-of-international-cyber-crime-takedown | 2026-11-12; 2026-11-13 | Confirmed (the arrests; the figures are the government's) |
| 33 | US-CERT (CISA archive), Microsoft Releases Security Advisory for Microsoft Digital Certificates, 12 Jul 2012 | https://www.cisa.gov/news-events/alerts/2012/07/12/microsoft-releases-security-advisory-microsoft-digital-certificates | 2026-11-13 | Confirmed |
| 34 | Kaspersky (Securelist) with Seculert, The Madi Campaign, Part I, 17 Jul 2012 | https://securelist.com/the-madi-campaign-part-i-5/33693/ | 2026-11-12; 2026-11-13 | Confirmed (the researchers' findings) |
| 35 | Dropbox blog, Security update and new features, 31 Jul 2012 | https://blog.dropbox.com/topics/company/security-update-new-features | 2026-11-12; 2026-11-13 | Confirmed (the company's account) |
| 36 | Kaspersky (Securelist), Gauss: Nation-state cyber-surveillance meets banking Trojan, 9 Aug 2012 | https://securelist.com/gauss-nation-state-cyber-surveillance-meets-banking-trojan-54/33854/ | 2026-11-13 | Confirmed (the vendor's findings) |
| 37 | Kaspersky (Securelist), Gauss: Abnormal Distribution, 9 Aug 2012 | https://securelist.com/gauss-abnormal-distribution/36620/ | 2026-11-12 | Confirmed (the vendor's findings); Reported (its nation-state judgment) |
| 38 | NVD, CVE-2012-1535 (API record) | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2012-1535` | 2026-11-13 | Confirmed |
| 39 | Kaspersky (Securelist), Shamoon the Wiper: Copycats at Work, 16 Aug 2012 (updated 17 Aug) | https://securelist.com/shamoon-the-wiper-copycats-at-work/57854/ | 2026-11-12; 2026-11-13 | Confirmed (the vendor's findings) |
| 40 | MITRE ATT&CK, S0140 Shamoon | https://attack.mitre.org/software/S0140/ | 2026-11-12; 2026-11-13 | Confirmed (the object and its techniques); Reported (the attribution) |
| 41 | US-CERT (CISA archive), TA12-240A, Oracle Java 7 Security Manager Bypass Vulnerability, 27 Aug 2012 (updated 28 Aug and 5 Sep) | https://www.cisa.gov/news-events/alerts/2012/08/27/oracle-java-7-security-manager-bypass-vulnerability | 2026-11-13 | Confirmed |
| 42 | CERT/CC, VU#636312, Oracle Java JRE 1.7 fails to restrict access to privileged code | https://www.kb.cert.org/vuls/id/636312 | 2026-11-12 | Confirmed |
| 43 | Oracle, Security Alert for CVE-2012-4681, Rev 1, 30 Aug 2012 | https://www.oracle.com/security-alerts/alert-cve-2012-4681.html | 2026-11-12 | Confirmed |
| 44 | NVD, CVE-2012-4681 (API record) | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2012-4681` | 2026-11-12 | Confirmed |
| 45 | MITRE ATT&CK, G0066 Elderwood | https://attack.mitre.org/groups/G0066/ | 2026-11-12; 2026-11-13 | Confirmed (the object and its techniques); Reported (the China attribution) |
| 46 | Symantec, The Elderwood Project, 6 Sep 2012 (Internet Archive copy) | https://web.archive.org/web/20190717233006if_/http://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/the-elderwood-project.pdf | 2026-11-12 | Confirmed (the vendor's findings) |
| 47 | Microsoft Security Advisory 2757760, Vulnerability in Internet Explorer Could Allow Remote Code Execution, 17 Sep 2012 (v2.0 21 Sep) | https://learn.microsoft.com/en-us/security-updates/securityadvisories/2012/2757760 | 2026-11-12; 2026-11-13 | Confirmed |
| 48 | Microsoft Security Bulletin MS12-063, 21 Sep 2012 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-063 | 2026-11-12 | Confirmed (the date); Inferred (out of band) |
| 49 | NVD, CVE-2012-4969 (API record) | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2012-4969` | 2026-11-12 | Confirmed |
| 50 | US-CERT (CISA archive), Increased Exploitation of Web Content Management Systems, 21 Sep 2012 | https://www.cisa.gov/news-events/alerts/2012/09/21/increased-exploitation-web-content-management-systems | 2026-11-12; 2026-11-13 | Confirmed |
| 51 | US-CERT (CISA archive), Adobe Releases Security Bulletin about Code Signing Certificate, 28 Sep 2012 | https://www.cisa.gov/news-events/alerts/2012/09/28/adobe-releases-security-bulletin-about-code-signing-certificate | 2026-11-13 | Confirmed |
| 52 | PNC Financial Services, Form 10-Q, filed 8 Nov 2012 (SEC EDGAR) | `https://www.sec.gov/Archives/edgar/data/713676/000119312512460110/d407118d10q.htm` | 2026-11-13 | Confirmed |
| 53 | Capital One Financial, Form 10-K for 2012, filed 28 Feb 2013 (SEC EDGAR) | `https://www.sec.gov/Archives/edgar/data/927628/000119312513084249/d447949d10k.htm` | 2026-11-13 | Confirmed |
| 54 | Barnes & Noble, Form 10-Q, filed 6 Dec 2012 (SEC EDGAR) | `https://www.sec.gov/Archives/edgar/data/890491/000119312512493181/d435954d10q.htm` | 2026-11-13 | Confirmed |
| 55 | CISA, Known Exploited Vulnerabilities catalog (JSON feed, version 2026.11.10) | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | 2026-11-12; 2026-11-13 | Confirmed |
| 56 | FBI, Most Wanted: Iranian DDoS Attacks (2016 SDNY indictment) | https://www.fbi.gov/wanted/cyber/iranian-ddos-attacks | 2026-11-12 | Confirmed (as charged) |
| 57 | US v. Fathi and others, SDNY indictment (2016) | https://www.justice.gov/opa/file/834996/download | 2026-11-12 | Confirmed (as alleged) |
| 58 | Mandiant, APT1: Exposing One of China's Cyber Espionage Units, Feb 2013 | https://services.google.com/fh/files/misc/mandiant-apt1-report.pdf | 2026-11-12 | Confirmed (the vendor's findings and attributions) |
| 59 | FBI, Most Wanted: Wang Dong (2014 W.D. Pa. indictment of five 3PLA officers) | https://www.fbi.gov/wanted/cyber/wang-dong | 2026-11-12 | Confirmed (as charged) |
| 60 | US v. Wang Dong and others, W.D. Pa. indictment (2014) | https://www.justice.gov/iso/opa/resources/5122014519132358461949.pdf | 2026-11-12 | Confirmed (as alleged) |
| 61 | MITRE ATT&CK, G0006 APT1 | https://attack.mitre.org/groups/G0006/ | 2026-11-12 | Confirmed |
| 62 | CVE Program, CVE-2012-1889 record (CVE API; with the CVE-2012-0779, CVE-2012-1875 and CVE-2012-1535 records) | https://cveawg.mitre.org/api/cve/CVE-2012-1889 | 2026-11-12 | Confirmed |
| 63 | Kaspersky (Securelist), "Red October" Diplomatic Cyber Attacks Investigation | https://securelist.com/red-october-diplomatic-cyber-attacks-investigation/36740/ | 2026-11-12 | Confirmed (the vendor's findings); Reported (the origin judgment) |
| 64 | Kaspersky (Securelist), The Epic Turla Operation, Aug 2014 | https://securelist.com/the-epic-turla-operation/65545/ | 2026-11-12 | Confirmed (the vendor's findings) |
| 65 | UK Government, UK exposes Russian spy agency behind cyber incidents, 24 Mar 2022 | https://www.gov.uk/government/news/uk-exposes-russian-spy-agency-behind-cyber-incidents | 2026-11-12 | Confirmed |
| 66 | Google Online Security Blog, Security warnings for suspected state-sponsored attacks, 5 Jun 2012 | https://security.googleblog.com/2012/06/security-warnings-for-suspected-state.html | 2026-11-12 | Confirmed (title and date only) |
| 67 | TeamStarWolf library, ATT&CK groups data (`data/attack/groups.jsonl`, v20.0) | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/attack/groups.jsonl | 2026-11-12; 2026-11-13 | Confirmed (ATT&CK's descriptions); Demonstrated |
| 68 | MITRE ATT&CK, G0003 Cleaver | https://attack.mitre.org/groups/G0003/ | 2026-11-12 | Confirmed |
| 69 | Microsoft Security Bulletin MS12-020, 13 Mar 2012 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-020 | 2026-11-12 | Confirmed |
| 70 | Microsoft Security Bulletin MS12-034, 8 May 2012 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-034 | 2026-11-12 | Confirmed |
| 71 | Microsoft Security Bulletin MS12-037, 12 Jun 2012 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-037 | 2026-11-12 | Confirmed |
| 72 | Microsoft Security Bulletin MS12-083, 11 Dec 2012 (with the year's numbering) | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-083 | 2026-11-12 | Confirmed (dates); Inferred (the count) |
| 73 | NVD, CVE-2012-4792 (API record) | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2012-4792` | 2026-11-12 | Confirmed |
| 74 | CERT/CC, VU#520827, PHP-CGI query string parameter vulnerability | https://www.kb.cert.org/vuls/id/520827 | 2026-11-12 | Confirmed |
| 75 | PHP, news archive for 2012 | https://www.php.net/archive/2012.php | 2026-11-12 | Confirmed |
| 76 | Apache Struts, S2-008 | https://cwiki.apache.org/confluence/display/WW/S2-008 | 2026-11-12 | Confirmed |
| 77 | FBI, New Internet Scam (Reveton), 9 Aug 2012 | https://www.fbi.gov/news/stories/new-internet-scam | 2026-11-12 | Confirmed |
| 78 | FBI, Ransomware on the Rise | https://www.fbi.gov/news/stories/ransomware-on-the-rise | 2026-11-12 | Confirmed |
| 79 | MITRE ATT&CK, S0484 Carberp | https://attack.mitre.org/software/S0484/ | 2026-11-12 | Confirmed |
| 80 | FTC, FTC files complaint against Wyndham Hotels for failure to protect consumers' personal information, 26 Jun 2012 | `https://www.ftc.gov/news-events/news/press-releases/2012/06/ftc-files-complaint-against-wyndham-hotels-failure-protect-consumers-personal-information` | 2026-11-12 | Confirmed (as alleged) |
| 81 | House Committee on Oversight and Government Reform, Timeline of Key Events (OPM), Sep 2016 | https://oversight.house.gov/wp-content/uploads/2016/09/Timeline-of-Key-Events-.pdf | 2026-11-12 | Confirmed |
| 82 | ICS-CERT (CISA), ICS-ALERT-12-020-01, Control System Vulnerabilities Disclosed at S4 (Project Basecamp) | https://www.cisa.gov/news-events/ics-alerts/ics-alert-12-020-01 | 2026-11-12 | Confirmed |
| 83 | ICS-CERT (CISA), ICS-ALERT-12-195-01, Tridium Niagara AX | https://www.cisa.gov/news-events/ics-alerts/ics-alert-12-195-01 | 2026-11-12 | Confirmed; date Inferred |
| 84 | KrebsOnSecurity, Chinese hackers blamed for intrusion at energy industry giant Telvent, 26 Sep 2012 | https://krebsonsecurity.com/2012/09/chinese-hackers-blamed-for-intrusion-at-energy-industry-giant-telvent/ | 2026-11-12 | Reported |
| 85 | FBI, Most Wanted: Hamid Firoozi | https://www.fbi.gov/wanted/cyber/hamid-firoozi | 2026-11-12 | Confirmed |
| 86 | US-CERT (CISA archive), Best Practices for Recovery from the Malicious Erasure of Files, 19 Jan 2012 | https://www.cisa.gov/news-events/alerts/2012/01/19/best-practices-recovery-malicious-erasure-files | 2026-11-12 | Confirmed |
| 87 | European Commission, IP/12/46, Commission proposes reform of the data protection rules, 25 Jan 2012 | https://ec.europa.eu/commission/presscorner/api/documents?reference=IP/12/46&language=en | 2026-11-12 | Confirmed (the proposal; the savings figure is the Commission's claim) |
| 88 | European Commission, IP/12/317, European Cybercrime Centre proposal, 28 Mar 2012 | https://ec.europa.eu/commission/presscorner/api/documents?reference=IP/12/317&language=en | 2026-11-12 | Confirmed |
| 89 | Clerk of the US House, Roll Call 192, H.R. 3523, 26 Apr 2012 | https://clerk.house.gov/Votes/2012192 | 2026-11-12 | Confirmed |
| 90 | US Senate, Roll Call Vote 187, 112th Congress, 2nd session (S. 3414 cloture), 2 Aug 2012 | https://www.senate.gov/legislative/LIS/roll_call_votes/vote1122/vote_112_2_00187.htm | 2026-11-12 | Confirmed |
| 91 | NIST, SP 800-61 Rev. 2, Computer Security Incident Handling Guide, Aug 2012 | https://csrc.nist.gov/pubs/sp/800/61/r2/final | 2026-11-12 | Confirmed |
| 92 | NIST, SP 800-30 Rev. 1, Guide for Conducting Risk Assessments, 17 Sep 2012 | https://csrc.nist.gov/pubs/sp/800/30/r1/final | 2026-11-12 | Confirmed |
| 93 | ITU, World Conference on International Telecommunications (WCIT-12) | https://www.itu.int/en/wcit-12/Pages/default.aspx | 2026-11-12 | Confirmed |
| 94 | NIST, FIPS 180-4, Secure Hash Standard, 6 Mar 2012 | https://csrc.nist.gov/pubs/fips/180-4/final | 2026-11-12 | Confirmed |
| 95 | NIST, NIST selects winner of Secure Hash Algorithm (SHA-3) competition, 2 Oct 2012 | https://www.nist.gov/news-events/news/2012/10/nist-selects-winner-secure-hash-algorithm-sha-3-competition | 2026-11-12 | Confirmed |
| 96 | IETF, RFC 6520, TLS and DTLS Heartbeat Extension, Feb 2012 | https://www.rfc-editor.org/rfc/rfc6520.txt | 2026-11-12 | Confirmed |
| 97 | IETF, RFC 6698, The DNS-Based Authentication of Named Entities (DANE) TLS Protocol: TLSA, Aug 2012 | https://www.rfc-editor.org/rfc/rfc6698.txt | 2026-11-12 | Confirmed |
| 98 | IETF, RFC 6749, The OAuth 2.0 Authorization Framework, Oct 2012 | https://www.rfc-editor.org/rfc/rfc6749.txt | 2026-11-12 | Confirmed |
| 99 | IETF, RFC 6797, HTTP Strict Transport Security (HSTS), Nov 2012 | https://www.rfc-editor.org/rfc/rfc6797.txt | 2026-11-12 | Confirmed |
| 100 | MITRE, CWE news archive for 2012 | https://cwe.mitre.org/news/archives/news2012.html | 2026-11-12 | Confirmed |
| 101 | MITRE, CAPEC news archive for 2012 | https://capec.mitre.org/news/archives/news2012.html | 2026-11-12 | Confirmed |
| 102 | NIST, SP 800-53 Rev. 4, final 30 Apr 2013 | https://csrc.nist.gov/pubs/sp/800/53/r4/final | 2026-11-12 | Confirmed (no 2012 draft listed) |
| 103 | Microsoft Security Advisory 2661254, Update For Minimum Certificate Key Length, 14 Aug 2012 (revised 11 Sep; v2.0 9 Oct) | https://learn.microsoft.com/en-us/security-updates/securityadvisories/2012/2661254 | 2026-11-12 | Confirmed |
| 104 | NVD, CVE-2012-0158 (API record) | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2012-0158` | 2026-11-12 | Confirmed |
| 105 | NVD, CVE-2012-0002 (API record) | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2012-0002` | 2026-11-12 | Confirmed |
| 106 | NVD, CVE-2012-1889 and CVE-2012-0754 (API records) | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2012-1889` ; `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2012-0754` | 2026-11-12 | Confirmed |
| 107 | NVD, CVE-2012-4929, CRIME (API record) | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2012-4929` | 2026-11-12 | Confirmed |
| 108 | NVD, CVE API query by publication date, 2012 (four windows; first window shown) | `https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=2012-01-01T00:00:00.000&pubEndDate=2012-04-29T23:59:59.999` | 2026-11-12 | Confirmed (query result) |
| 109 | MITRE ATT&CK, G0096 APT41 | https://attack.mitre.org/groups/G0096 | 2026-11-12 | Confirmed |
| 110 | MITRE ATT&CK, C0016 Operation Dust Storm | https://attack.mitre.org/campaigns/C0016 | 2026-11-12 | Confirmed |
| 111 | MITRE ATT&CK, T1189 Drive-by Compromise | https://attack.mitre.org/techniques/T1189/ | 2026-11-12 | Confirmed (the technique); Inferred (its binding to 2012 events beyond G0066) |
| 112 | MITRE CAPEC, CAPEC-459 Creating a Rogue Certification Authority Certificate | https://capec.mitre.org/data/definitions/459.html | 2026-11-12 | Confirmed (the pattern); Inferred (its binding) |
| 113 | MITRE CWE, CWE-416 Use After Free | https://cwe.mitre.org/data/definitions/416.html | 2026-11-12 | Confirmed |
| 114 | MITRE D3FEND, Certificate Pinning | https://d3fend.mitre.org/technique/d3f:CertificatePinning/ | 2026-11-12 | Confirmed |
| 115 | TeamStarWolf library, case studies on main (home studies named in the text) | https://github.com/TeamStarWolf/TeamStarWolf/tree/main/case-studies | 2026-11-12; 2026-11-13 | Confirmed (for the fact that a study is the home and for the facts it carries from its own sources); Reported (the Unit 42 figure it carries) |
| 116 | TeamStarWolf library, ATT&CK, ICS, weakness and countermeasure data (`data/attack/`, `data/attack/ics/`, `data/weaknesses/`, `data/attack/technique_to_d3fend.jsonl`) | https://github.com/TeamStarWolf/TeamStarWolf/tree/main/data/attack | 2026-11-12; 2026-11-13 | Demonstrated |
| 117 | TeamStarWolf library, `mitre/` page tree (technique, group, software, campaign, CAPEC, D3FEND and mitigation pages) | https://github.com/TeamStarWolf/TeamStarWolf/tree/main/mitre | 2026-11-12; 2026-11-13 | Demonstrated |
| 118 | TeamStarWolf library, chronicle Navigator layers (`navigator/library-layers/chronicle-2016.json` and the later years) | https://github.com/TeamStarWolf/TeamStarWolf/tree/main/navigator/library-layers | 2026-11-13 | Demonstrated |

*© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.*

*© The MITRE Corporation. Includes material from the Common Weakness Enumeration (CWE™), used under the CWE Terms of Use. https://cwe.mitre.org/*

*© The MITRE Corporation. Includes material from the Common Attack Pattern Enumeration and Classification (CAPEC™), used under the CAPEC Terms of Use. https://capec.mitre.org/*

*© The MITRE Corporation. Includes material from MITRE D3FEND™, used under the D3FEND Terms of Use. https://d3fend.mitre.org/*

*The terms for every MITRE dataset used here are recorded in [THIRD_PARTY_NOTICES.md](/THIRD_PARTY_NOTICES.md).*

## Related references

- [Notable Incidents](/NOTABLE_INCIDENTS.md), [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [CVE Reference](/CVE_REFERENCE.md)
- [Certificate Trust Incident Response](/CERTIFICATE_TRUST_INCIDENT_RESPONSE_REFERENCE.md), [Cryptography](/CRYPTOGRAPHY_REFERENCE.md), [Browser Security](/BROWSER_SECURITY_REFERENCE.md), [Email Security](/EMAIL_SECURITY_REFERENCE.md), [Identity and Access Management](/IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md), [Web Application Security](/WEB_APPLICATION_SECURITY_REFERENCE.md), [CWE Reference](/CWE_REFERENCE.md), [CAPEC Reference](/CAPEC_REFERENCE.md), [D3FEND Reference](/D3FEND_REFERENCE.md), [GRC and Compliance](/GRC_COMPLIANCE_REFERENCE.md), [Vulnerability Management](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [Incident Response](/INCIDENT_RESPONSE_REFERENCE.md), [ICS/OT Security](/ICS_OT_SECURITY_REFERENCE.md)
- Home studies: [Stuxnet](/case-studies/STUXNET.md); [United States-attributed threat actors](/case-studies/THREAT_ACTORS_UNITED_STATES.md); [Iran-attributed threat actors](/case-studies/THREAT_ACTORS_IRAN.md); [China-attributed threat actors](/case-studies/THREAT_ACTORS_CHINA.md); [Russia-attributed threat actors](/case-studies/THREAT_ACTORS_RUSSIA.md); [Other states' threat actors](/case-studies/THREAT_ACTORS_OTHER_STATES.md); [The Hacker and the State](/case-studies/HACKER_AND_THE_STATE_CASES.md); [The Zero-Day Market](/case-studies/ZERO_DAY_MARKET_EVENTS.md); [Four Books on Cybercrime](/case-studies/CYBERCRIME_FOUR_BOOKS.md); [Cloud Security Incidents](/case-studies/CLOUD_SECURITY_INCIDENTS.md); [E-Commerce Threats](/case-studies/ECOMMERCE_THREATS.md); [Ransomware ecosystem](/case-studies/RANSOMWARE_ECOSYSTEM.md); [APT41](/case-studies/APT41_PUBLIC_RECORD.md); [ICS attacks and advisories](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md); [Log4Shell](/case-studies/LOG4SHELL.md); [SolarWinds SUNBURST](/case-studies/SOLARWINDS_SUNBURST.md); [npm supply-chain attacks](/case-studies/NPM_SUPPLY_CHAIN_ATTACKS.md); [Hugging Face supply chain](/case-studies/HUGGING_FACE_SUPPLY_CHAIN.md)
- Series: [1993](/case-studies/CHRONICLE_1993.md), [1994](/case-studies/CHRONICLE_1994.md), [1995](/case-studies/CHRONICLE_1995.md), [1996](/case-studies/CHRONICLE_1996.md), [1997](/case-studies/CHRONICLE_1997.md), [1998](/case-studies/CHRONICLE_1998.md), [1999](/case-studies/CHRONICLE_1999.md), [2000](/case-studies/CHRONICLE_2000.md), [2001](/case-studies/CHRONICLE_2001.md), [2002](/case-studies/CHRONICLE_2002.md), [2003](/case-studies/CHRONICLE_2003.md), [2004](/case-studies/CHRONICLE_2004.md), [2005](/case-studies/CHRONICLE_2005.md), [2006](/case-studies/CHRONICLE_2006.md), [2007](/case-studies/CHRONICLE_2007.md), [2010](/case-studies/CHRONICLE_2010.md), [2016](/case-studies/CHRONICLE_2016.md), [2017](/case-studies/CHRONICLE_2017.md), [2018](/case-studies/CHRONICLE_2018.md), [2019](/case-studies/CHRONICLE_2019.md), [2020](/case-studies/CHRONICLE_2020.md), [2021](/case-studies/CHRONICLE_2021.md), [2022](/case-studies/CHRONICLE_2022.md), [2023](/case-studies/CHRONICLE_2023.md), [2024](/case-studies/CHRONICLE_2024.md), [2025](/case-studies/CHRONICLE_2025.md), [2026](/case-studies/CHRONICLE_2026.md)
- Techniques: [T1189 Drive-by Compromise](/mitre/techniques/T1189.md), [T1203 Exploitation for Client Execution](/mitre/techniques/T1203.md), [T1566.001 Spearphishing Attachment](/mitre/techniques/T1566-001.md), [T1566.002 Spearphishing Link](/mitre/techniques/T1566-002.md), [T1588.004 Digital Certificates](/mitre/techniques/T1588-004.md), [T1553.002 Code Signing](/mitre/techniques/T1553-002.md), [T1091 Replication Through Removable Media](/mitre/techniques/T1091.md), [T1485 Data Destruction](/mitre/techniques/T1485.md), [T1561.002 Disk Structure Wipe](/mitre/techniques/T1561-002.md), [T1498 Network Denial of Service](/mitre/techniques/T1498.md), [T1498.001 Direct Network Flood](/mitre/techniques/T1498-001.md), [T1499.002 Service Exhaustion Flood](/mitre/techniques/T1499-002.md), [T1110.004 Credential Stuffing](/mitre/techniques/T1110-004.md), [T1190 Exploit Public-Facing Application](/mitre/techniques/T1190.md), [T1195 Supply Chain Compromise](/mitre/techniques/T1195.md), [T1036.002 Right-to-Left Override](/mitre/techniques/T1036-002.md), [T1114.002 Remote Email Collection](/mitre/techniques/T1114-002.md); the full list is in the Part 12 table
- CAPEC: [CAPEC-68](/mitre/capec/CAPEC-68.md), [CAPEC-125](/mitre/capec/CAPEC-125.md), [CAPEC-163](/mitre/capec/CAPEC-163.md), [CAPEC-206](/mitre/capec/CAPEC-206.md), [CAPEC-438](/mitre/capec/CAPEC-438.md), [CAPEC-439](/mitre/capec/CAPEC-439.md), [CAPEC-457](/mitre/capec/CAPEC-457.md), [CAPEC-459](/mitre/capec/CAPEC-459.md), [CAPEC-473](/mitre/capec/CAPEC-473.md), [CAPEC-486](/mitre/capec/CAPEC-486.md), [CAPEC-488](/mitre/capec/CAPEC-488.md), [CAPEC-555](/mitre/capec/CAPEC-555.md), [CAPEC-560](/mitre/capec/CAPEC-560.md), [CAPEC-581](/mitre/capec/CAPEC-581.md), [CAPEC-600](/mitre/capec/CAPEC-600.md), [CAPEC-634](/mitre/capec/CAPEC-634.md), [CAPEC-648](/mitre/capec/CAPEC-648.md)
- Groups, software and campaigns: Flame [S0143](/mitre/software/S0143.md); Shamoon [S0140](/mitre/software/S0140.md); Elderwood [G0066](/mitre/groups/G0066.md); APT1 [G0006](/mitre/groups/G0006.md); Hydraq [S0203](/mitre/software/S0203.md); PoisonIvy [S0012](/mitre/software/S0012.md); Carberp [S0484](/mitre/software/S0484.md); APT41 [G0096](/mitre/groups/G0096.md); Kimsuky [G0094](/mitre/groups/G0094.md); APT37 [G0067](/mitre/groups/G0067.md); Mustang Panda [G0129](/mitre/groups/G0129.md); Dragonfly [G0035](/mitre/groups/G0035.md); Tonto Team [G0131](/mitre/groups/G0131.md); Operation Dust Storm [C0016](/mitre/campaigns/C0016.md)
- [Navigator layers](/navigator/index.md), including this study's layer, [chronicle-2012.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/chronicle-2012.json)
