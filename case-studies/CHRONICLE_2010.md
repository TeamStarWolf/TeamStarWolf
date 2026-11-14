# The Year 2010 in Intrusions: A Dated Record

*A TeamStarWolf case study. Published 13 November 2026; every source checked as of that date.*

[All case studies](/case-studies/README.md) · Related: [Notable Incidents](/NOTABLE_INCIDENTS.md), [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [CVE Reference](/CVE_REFERENCE.md), [Cryptography](/CRYPTOGRAPHY_REFERENCE.md), [GRC and Compliance](/GRC_COMPLIANCE_REFERENCE.md), [Incident Response](/INCIDENT_RESPONSE_REFERENCE.md), [Vulnerability Management](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [ICS/OT Security](/ICS_OT_SECURITY_REFERENCE.md) · Home studies for events summarized here: [The Zero-Day Trade and Its Fallout](/case-studies/ZERO_DAY_MARKET_EVENTS.md) (Operation Aurora and the Clinton speech), [Stuxnet](/case-studies/STUXNET.md) (Stuxnet), [Four Books on Cybercrime](/case-studies/CYBERCRIME_FOUR_BOOKS.md) (Max Butler and Operation Avenge Assange), [E-Commerce Threats](/case-studies/ECOMMERCE_THREATS.md) (Heartland and the Gonzalez ring), [China-attributed threat actors](/case-studies/THREAT_ACTORS_CHINA.md) (Night Dragon) · Series: [The Year 2006 in Intrusions](/case-studies/CHRONICLE_2006.md), [The Year 2007 in Intrusions](/case-studies/CHRONICLE_2007.md), [The Year 2016 in Intrusions](/case-studies/CHRONICLE_2016.md) and the other years in the [case studies index](/case-studies/README.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Threat intelligence analysts, security historians, vulnerability management, ICS and web security teams and anyone who wants the history behind current threats

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Beginner to intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 66 min (15,189 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want a dated record of the intrusions of 2010, you need Operation Aurora, Stuxnet's 2010 dates and the year's exploited browser, document and Windows flaws side by side with the Zeus, Waledac and Mariposa cases, the espionage reports that stopped short of a state finding, the defaults and standards that followed, or you want the defender lessons that still apply

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [Part 2: the vulnerability record](#part-2-the-vulnerability-record), [Part 5: the state and espionage record](#part-5-the-state-and-espionage-record)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Notable Incidents](/NOTABLE_INCIDENTS.md), [Stuxnet](/case-studies/STUXNET.md), [ICS/OT Security](/ICS_OT_SECURITY_REFERENCE.md), [The Year 2007 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2007.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive summary

The year opened with a disclosure about the year before. On 12 January Google said that in mid-December 2009 it had detected a highly sophisticated, targeted attack on its corporate infrastructure originating from China that resulted in the theft of intellectual property, that at least twenty other large companies in the internet, finance, technology, media and chemical sectors had been similarly targeted, and that a primary goal appeared to be the Gmail accounts of Chinese human rights activists, only two of which appear to have been accessed (Confirmed [1]). Microsoft's Advisory 979352 followed on 14 January, NVD published CVE-2010-0249 on 15 January as an Internet Explorer use-after-free "exploited in the wild in December 2009 and January 2010 during Operation Aurora", and MS10-002 fixed it on 21 January (Confirmed [3][5][4]). The same day the Secretary of State said that countries or individuals that engage in cyber attacks should face consequences and international condemnation (Confirmed [9]). On 22 March Google stopped censoring search on Google.cn and redirected users to Google.com.hk (Confirmed [2]). ATT&CK says the Elderwood group was "reportedly responsible" (Confirmed that ATT&CK says so [11]; the attribution is Reported). CISA added CVE-2010-0249 to its Known Exploited Vulnerabilities catalog on 20 May 2026 (Confirmed [8]). The [Zero-Day Trade](/case-studies/ZERO_DAY_MARKET_EVENTS.md) study is the home for Aurora.

The year's defining malware arrived on a USB stick. Symantec's dossier records that VirusBlokAda reported the malware on 17 June; Microsoft's Advisory 2286198 on the Windows shortcut flaw CVE-2010-2568 followed on 16 July, ICS-CERT said the trojan interacted with Siemens SIMATIC WinCC and STEP 7, and out-of-band bulletin MS10-046 shipped on 2 August, when "a number of malware families" were already exploiting the flaw (Confirmed [30][24][22][25]). By the time Symantec published its analysis on 30 September it counted about 100,000 infected hosts, roughly 60 percent of them in Iran (Confirmed [30]). The [Stuxnet](/case-studies/STUXNET.md) study is the home; this chronicle records the 2010 dates and the defender record.

Crime was prosecuted at scale and in public. Max Butler was sentenced to 13 years on 12 February, Albert Gonzalez to 20 years on 25 March, and a federal judge granted Microsoft a restraining order on 22 February that cut off 277 domains of the Waledac spam botnet (Confirmed [13][66][15]). Spanish and Slovenian police arrested the suspected Mariposa operators and creator (Confirmed [16]). On 30 September prosecutors in New York charged 37 defendants over Zeus-enabled bank fraud, and the next day the FBI said a Zeus-based ring had stolen USD 70 million and attempted about USD 220 million (Confirmed [42][43][44]). In December, as later charged, Anonymous ran denial-of-service attacks on PayPal after it suspended the WikiLeaks account (Confirmed as charged [46]).

Espionage was documented by researchers and a congressional commission, and neither made a finding of state responsibility; the commission offered an assessment, not a finding (Confirmed [18][10]). "Shadows in the Cloud" of 6 April documented a network that compromised systems in India's national security establishment, the Offices of the Dalai Lama and the United Nations, and placed the attackers in Chengdu only by circumstantial evidence (Confirmed [18]; the location is Reported). The US-China Economic and Security Review Commission said China Telecom advertised erroneous routes for about 18 minutes on 8 April that sent traffic for about 15 percent of internet destinations through Chinese servers, and that it could not determine what, if anything, was done with the traffic (Confirmed [10]). On 1 September the Deputy Secretary of Defense disclosed that an infected flash drive had compromised US Central Command networks in 2008 (Confirmed [38]).

The web's defaults moved. Gmail began turning on HTTPS by default for all users on 12 January, Chromium launched a vulnerability reward program on 28 January, RFC 5746 fixed TLS renegotiation in February, HTTPS Everywhere shipped on 17 June, the signed DNS root's first trust anchor became valid on 15 July, and on 24 October Firesheep showed how easily session cookies could be taken on open Wi-Fi (Confirmed [76][74][70][77][73][68]). Governments organized: NIST published SP 800-37 Revision 1 in February, US Cyber Command began operations in May, NIST published its smart grid guidelines on 31 August, DHS ran Cyber Storm III from 27 September, and the UK committed GBP 650 million of new funds to cyber security on 19 October (Confirmed [69][38][78][79][80]).

This study records the year by date. It is built only from sources opened on 12 November 2026 and from checks of the library's data run on 12 and 13 November 2026, and is checked as of 13 November 2026.

### Key facts at a glance

| Field | Value |
|---|---|
| Period | 1 January to 31 December 2010, plus the records that open, close or explain a 2010 event: Google's December 2009 detection, the 2008 CENTCOM flash-drive compromise disclosed in 2010, the 2011 charging releases for the AT&T iPad exposure and the PayPal attacks, Symantec's dossier v1.4 (February 2011), and KEV additions from 2021 to 2026 |
| The headline disclosure | Aurora: Google's post (12 Jan); Advisory 979352 (14 Jan); NVD CVE-2010-0249 (15 Jan); MS10-002 and the Clinton speech (21 Jan); Google.cn redirect (22 Mar) (Confirmed [1][3][5][4][9][2]) |
| Stuxnet in 2010 | VirusBlokAda report (17 Jun); CERT/CC VU#940193 (15 Jul); Advisory 2286198 and US-CERT alert (16 Jul); MS10-046 (2 Aug); MS10-061 (14 Sep); Symantec dossier (30 Sep) (Confirmed [30][26][24][23][25][31]) |
| Exploited at or before the fix | Microsoft CVE-2010-0249, -0806, -1885, -2568, -2729, -2743, -3332, -3338, -3962; Mozilla CVE-2010-3765; Adobe CVE-2010-1297, -2883, -3654 (Confirmed [4][52][21][25][31][53][39][55][45][56][60][62][63]) |
| Microsoft's year | MS10-001 (12 Jan) to MS10-106 (14 Dec): 106 bulletins by numbering; October alone carried 16 bulletins with 49 vulnerability sections (Confirmed [49][50]; counts Inferred) |
| KEV tail | 23 CVE-2010 entries in catalog 2026.11.10, four flagged for known ransomware use; CVE-2010-0249 and CVE-2010-0806 added on 20 May 2026 (Confirmed [8]) |
| Crime and prosecutions | Butler (12 Feb); Waledac order (22 Feb); Gonzalez (25 Mar) and Scott (29 Mar); Mariposa arrests (Feb and Jul); Zeus charges (30 Sep) and Trident Breach (1 Oct); PayPal attacks (6 to 10 Dec, charged 2011) (Confirmed [13][15][66][67][16][42][44][46]) |
| State and espionage | Aurora (detected Dec 2009); Shadows in the Cloud (6 Apr); China Telecom routes (8 Apr); Night Dragon (Nov 2009 to Feb 2011); Buckshot Yankee disclosed (1 Sep) (Confirmed [1][18][10][47][38]) |
| Web and open source | Apache JIRA attack (5 to 9 Apr); AT&T iPad enumeration (5 to 9 Jun); DLL preloading advisory (23 Aug); ASP.NET padding oracle (17 Sep); Twitter onMouseOver (21 Sep); Firesheep (24 Oct) (Confirmed [17][20][37][39][41][68]) |
| Defaults and incentives | Gmail HTTPS by default (12 Jan); Chromium rewards (28 Jan); RFC 5746 (Feb); HTTPS Everywhere (17 Jun); KSK-2010 valid (15 Jul); Mozilla USD 3,000 bounty (15 Jul) (Confirmed [76][74][70][77][73][75]) |
| Law, policy and standards | SP 800-37 Rev. 1 (Feb); CWE/SANS Top 25 (29 Mar); OWASP Top 10 (Apr); Cyber Command operating (May); NISTIR 7628 (31 Aug); Cyber Storm III (27 Sep to 1 Oct); UK SDSR (19 Oct) (Confirmed [69][71][72][38][78][79][80]) |
| Written later | ATT&CK's Flame (S0143) "active since at least 2010", disclosed in 2012; Operation Dust Storm (C0016) first seen January 2010 (Confirmed [48]; Demonstrated [84]) |
| This study's MITRE binding | 71 ATT&CK Enterprise techniques in 88 technique-tactic entries: 58 listed by ATT&CK for Elderwood (G0066), Hydraq (S0203), the Night Dragon campaign (C0002) or Stuxnet (S0603), seven described by a primary and assigned here, two from Reported sources, four inferred; ten ATT&CK for ICS techniques listed for Stuxnet; CWE ids from NVD and KEV; CAPEC and D3FEND pairings from the library's data; an Enterprise and an ATT&CK for ICS Navigator layer (Part 9) |

### Key findings

- **Aurora is a 2010 record of a 2009 attack.** Google detected it in mid-December 2009 and disclosed it on 12 January 2010; the advisory, the CVE record, the fix and the policy response all date from January 2010 (Confirmed [1][3][5][4][9]).
- **The fix came a week after the advisory, and KEV came sixteen years later.** Advisory 979352 is dated 14 January and MS10-002 21 January; KEV added CVE-2010-0249 on 20 May 2026 (Confirmed [3][4][8]).
- **Removable media reached the control room.** The shortcut flaw ran code when a USB drive was viewed in a file manager, without AutoRun, and the first malware to use it went after Siemens SIMATIC software (Confirmed [22][23]).
- **There was no fix for at least 17 days.** Advisory 2286198 came on 16 July, six days after CERT/CC's date public, and MS10-046 on 2 August; the workarounds MS10-046 records, and ICS-CERT's advice, were to turn off shortcut icon display and the WebClient service and to block shortcut files and outbound SMB (Confirmed [24][26][25][22]; the day count is Inferred).
- **Documents and browsers were exploited all year.** Internet Explorer, Firefox, Reader and Flash flaws were exploited at or before their fixes from January to December (Confirmed [4][52][45][56][60][62][63]).
- **Prosecution caught up with the carding era.** Butler was sentenced to 13 years in February and Gonzalez to 20 years in March, and New York charged 37 Zeus defendants in a single day in September (Confirmed [13][66][42]).
- **Takedowns moved into civil court.** Microsoft cut Waledac's domains through a temporary restraining order against John Does, not a criminal case (Confirmed [15]).
- **Researchers and a commission documented the espionage without a state finding.** Shadows in the Cloud names no state, and the USCC offers an assessment of Chinese government knowledge, not a finding (Confirmed [18][10]).
- **Encryption and integrity defaults moved in 2010.** Gmail's default HTTPS, HTTPS Everywhere, RFC 5746 and the signed root all date from this year, and Firesheep showed what was left unencrypted (Confirmed [76][77][70][73][68]).
- **KEV is still writing 2010 down.** Two 2010 ids entered KEV in 2026 and two in 2025; four of the 23 are flagged for known ransomware use (Confirmed [8]).

### Top recommendations

1. **Treat removable media as an entry point, not a convenience.** The 2010 shortcut flaw needed only a drive viewed in a file manager, and ICS-CERT's advice was to disable AutoRun, restrict privileges and be cautious with USB drives (Confirmed [22][23]).
2. **Apply the workaround while the fix is pending.** For at least 17 days after Advisory 2286198 the shortcut flaw had no fix, and the defenses MS10-046 and ICS-CERT list are workarounds: disable shortcut icons, WebClient and AutoRun (Confirmed [24][25][22]; Inferred for the count).
3. **Treat an advisory that says "limited, targeted attacks" as an emergency.** Advisories 979352, 2286198, 2416728 and 2458511 all preceded fixes for flaws already in use (Confirmed [3][24][39][45]).
4. **Encrypt sessions end to end, not just the login.** Firesheep took cookies that were sent in clear after an encrypted login, and its author argued that only full HTTPS fixes it (Confirmed [68]).
5. **Change default and hard-coded credentials in control software.** NVD says Stuxnet used a hard-coded password in Siemens WinCC and PCS 7 (Confirmed [33]).
6. **Patch the public-facing middleware you forgot.** JBoss, ColdFusion and Exim flaws from 2010 are in KEV, and the JBoss and ColdFusion entries are flagged for known ransomware use (Confirmed [8][59][61][64]).
7. **Watch for credential capture at online banking login.** Zeus recorded keystrokes at login and money mules moved the funds (Confirmed [42][43]).
8. **Lock down issue trackers and admin consoles.** Apache's JIRA attack combined a cross-site scripting link with a brute-force login on the same host (Confirmed [17]).
9. **Do not read KEV dates as event dates.** CVE-2010-0249 was exploited in 2009 and 2010 and listed in 2026 (Confirmed [5][8]).
10. **Read "originating from China" for what it says.** Google, the USCC and the Shadows report each stop short of a state finding (Confirmed [1][10][18]).

## Scope and method

This study covers intrusions, vulnerabilities, malware, botnets, card theft and fraud, prosecutions, state and espionage operations, defaults and incentives, regulation, standards and policy dated to 2010, plus the later records that open, close or explain a 2010 event. It follows the method of the [case studies collection](/case-studies/README.md): primary sources first, every claim graded, and numbers given as the source states them. Every external source was opened on 12 November 2026, and the library data checks were run on 12 and 13 November 2026. The Intelligence Hub feed, which carries 23 KEV rows for CVE-2010 ids and a historic row for the 16 July shortcut advisory, was used as a map to find primaries, not as a citation for any event (Confirmed [83]).

| Grade | Meaning in this study |
|---|---|
| Confirmed | The primary record was opened and states the fact: a vendor bulletin or advisory, a CERT/CC note, a US-CERT, ICS-CERT or CISA record, a CVE or NVD record, the KEV catalog, an FBI or US Attorney release, a court order as the plaintiff describes it, a congressional commission report, a government strategy or exercise report, an official's own statement, a researchers' or vendor's report stated as its own finding, a NIST, IETF, IANA, MITRE or OWASP record, a live ATT&CK page, or a library study, only for the fact that it is the home for an event |
| Reported | Only a secondary source supports the fact, or a source relays someone else's claim: World Nuclear News relaying Reuters, the Christian Science Monitor, the USCC quoting a vendor or Google's security manager, an FBI release quoting an industry estimate, and ATT&CK's "reportedly" attributions. The source is named in the text |
| Demonstrated | A check this study ran itself and saw the result (counts in the KEV catalog; id, name, tactic and page checks in the library's data files and `mitre/` page tree), or a public proof whose author shows the effect (Firesheep) |
| Inferred | The study's own reading, labelled where it appears. Every ATT&CK, CAPEC and D3FEND id bound to a 2010 event is Inferred as to the binding unless ATT&CK lists it for the object, and so is every CWE that NVD or KEV does not list |

Charges, complaints and indictments are allegations; where this study cites one, the record confirms that the charge was made, not that it was proven. Company statements are the company's own account, and vendor and researcher attributions are those authors' assessments, not government findings.

Limits a reader should know:

- **CVE existed; ATT&CK and KEV did not.** Every 2010 product flaw here carries a CVE id. No ATT&CK mapping existed in 2010, so every technique id in Part 9 is assigned in hindsight from later ATT&CK records or by this study (Inferred [5][11]). KEV's 2010 entries were added from November 2021 to May 2026 (Confirmed [8]).
- **Some events have no id of any kind.** The China Telecom route event, the Waledac takedown and the Clinton speech carry no CVE and no ATT&CK object, and the USCC makes no finding of intent for the routes (Confirmed [10][15][9]).
- **ICS-CERT's first Stuxnet advisory carries no original date on the page opened.** ICSA-10-201-01C shows only its 2014 revision, so this study dates its events from VirusBlokAda's report, CERT/CC and Microsoft (Confirmed [22][26][24]).
- **What was not checked.** No primary was opened, or the page would not open, for: the Justice Department's own release on the Gonzalez sentencing (the US Attorney's release of 16 April was used instead); Adobe's 2010 advisories and bulletins (APSA10-01, APSA10-02, APSA10-05, APSB10-07, APSB10-14 and APSB10-21) and its January 2010 post about its corporate network; the FTC's 2010 orders in the Twitter and Rite Aid matters; Massachusetts 201 CMR 17.00; the US Cyber Command history page and its exact initial and full operating dates; the DHS and DoD cybersecurity memorandum of October 2010; the Dutch Bredolab takedown; the UK Information Commissioner's first monetary penalties; the June 2010 arrests of ten alleged Russian agents; the "Here you have" mass-mailer; the Gawker breach; Koobface; PCI DSS 2.0; ISO/IEC 27003:2010; EMET 2.0; Symantec's Elderwood report and McAfee's Aurora analysis; the declassification date of the CNCI summary; Microsoft's October 2010 bulletin summary page; and a total count of 2010 CVE records. They are left out or marked "not checked" where they touch a verified fact. Their absence here is not evidence that nothing happened.

## Part 1: the year as a dated timeline

One row per event or report. The date is the event date where the source gives one, otherwise the publication date. Rows marked "frame" or "boundary" open or close a 2010 event.

| Date | Event | Thread | Sector | Grade | Sources |
|---|---|---|---|---|---|
| 2008 (frame) | An infected flash drive compromises CENTCOM classified and unclassified networks; Operation Buckshot Yankee responds (disclosed 1 Sep 2010) | State | Defense | Confirmed (official's statement) | [38] |
| 2009-11 to 2011-02 (frame) | ATT&CK's Night Dragon campaign against oil, energy and petrochemical companies. Home: [China-attributed threat actors](/case-studies/THREAT_ACTORS_CHINA.md) | State (China-based, per researchers) | Energy | Confirmed; attribution Reported | [47] |
| 2009-12 (frame) | Google detects a targeted attack on its corporate infrastructure (Operation Aurora); CVE-2010-0249 exploited in the wild from December | State (reportedly Elderwood) | Technology and others | Confirmed; attribution Reported | [1][5][11] |
| 2010-01 | ATT&CK's Operation Dust Storm (C0016) first seen | Espionage (unattributed) | Multiple | Demonstrated | [84] |
| 2010-01-08 | Heartland and Visa announce a settlement of up to USD 60 million for Visa issuers, as carried by the home study. Home: [E-Commerce Threats](/case-studies/ECOMMERCE_THREATS.md) | Card theft | Payments | Inferred (carried) | [82][87] |
| 2010-01-12 | Google discloses the attack; Gmail turns HTTPS on by default; MS10-001, the year's first bulletin | State; Defaults; Vulnerability | Technology | Confirmed | [1][76][49] |
| 2010-01-14 | Microsoft Advisory 979352 and CERT/CC VU#492515 on the Internet Explorer flaw; version 1.1 on 15 Jan cites limited targeted attacks | Vulnerability | Cross-sector (browsers) | Confirmed | [3][7] |
| 2010-01-15 | NVD and the CVE Program publish CVE-2010-0249, "exploited in the wild ... during Operation Aurora" | Vulnerability | Cross-sector | Confirmed | [5][6] |
| 2010-01-21 | MS10-002 fixes CVE-2010-0249 and seven other flaws; Secretary Clinton's Remarks on Internet Freedom. Home: [Zero-Day Trade](/case-studies/ZERO_DAY_MARKET_EVENTS.md) | Vulnerability; Policy | Cross-sector; government | Confirmed | [4][9] |
| 2010-01-28 | Chromium announces its vulnerability reward program | Incentives | Technology | Confirmed | [74] |
| 2010-02 | NIST SP 800-37 Revision 1; RFC 5746, TLS Renegotiation Indication Extension | Standards | Government; cross-sector | Confirmed | [69][70] |
| 2010-02 | Spanish Guardia Civil arrests three suspected Mariposa operators | Crime | Consumers, finance | Confirmed | [16] |
| 2010-02-09 | MS10-015 fixes the publicly disclosed kernel flaw CVE-2010-0232, with no exploitation known at release | Vulnerability | Cross-sector | Confirmed | [51] |
| 2010-02-12 | Max Ray Butler sentenced to 13 years and USD 27.5 million restitution. Home: [Four Books on Cybercrime](/case-studies/CYBERCRIME_FOUR_BOOKS.md) | Crime | Finance (carding) | Confirmed | [13] |
| 2010-02-21 | CVE-2010-0188 (Adobe Reader and Acrobat before 9.3.1) published | Vulnerability | Cross-sector | Confirmed | [58] |
| 2010-02-22 | E.D. Va. grants Microsoft's restraining order against the Waledac botnet's 277 domains (announced 24 Feb) | Botnet takedown | Technology, consumers | Confirmed (plaintiff's account) | [15] |
| 2010-03-25 | Albert Gonzalez sentenced to 20 years. Home: [E-Commerce Threats](/case-studies/ECOMMERCE_THREATS.md) | Crime | Retail, payments | Confirmed | [66] |
| 2010-03-29 | 2010 CWE/SANS Top 25; TJX conspirator Christopher Scott sentenced to seven years | Standards; Crime | Cross-sector; retail | Confirmed | [71][67] |
| 2010-03-30 | MS10-018 fixes CVE-2010-0806, which attackers were attempting to exploit | Vulnerability | Cross-sector (browsers) | Confirmed | [52] |
| 2010-04 | OWASP Top 10 2010 (release day from the PDF's metadata, approximate) | Standards | Web | Confirmed | [72] |
| 2010-04-05 to 2010-04-09 | Targeted attack on the Apache Software Foundation's JIRA host (reported 13 Apr) | Intrusion | Open-source software | Confirmed | [17] |
| 2010-04-06 | "Shadows in the Cloud" published (Citizen Lab op-ed on 7 Apr) | State (unattributed) | Government, NGO | Confirmed | [18][19] |
| 2010-04-08 | China Telecom advertises erroneous routes for about 18 minutes | Routing | Government, telecom | Confirmed (USCC's account) | [10] |
| 2010-04-28 | CVE-2010-0738, JBoss JMX-Console access control, published | Vulnerability | Cross-sector (servers) | Confirmed | [59] |
| 2010-05 | US Cyber Command begins operations under STRATCOM, per the Deputy Secretary of Defense | Policy | Defense | Confirmed (official's statement) | [38] |
| 2010-06-05 to 2010-06-09 | A script mimicking an iPad 3G harvests about 120,000 ICC-ID and e-mail pairs from AT&T's servers (charged 18 Jan 2011) | Exposure | Telecom | Confirmed (as charged) | [20] |
| 2010-06-08 | CVE-2010-1297 (Flash, Reader, Acrobat) published; exploited in the wild in June | Vulnerability | Cross-sector | Confirmed | [60] |
| 2010-06-17 | VirusBlokAda reports the malware later named Stuxnet; EFF and the Tor Project release HTTPS Everywhere. Home: [Stuxnet](/case-studies/STUXNET.md) | State; Defaults | Industrial; web | Confirmed | [30][77] |
| 2010-07-10 | Date the shortcut flaw became public, per CERT/CC | Vulnerability | Cross-sector | Confirmed | [26] |
| 2010-07-13 | MS10-042 fixes CVE-2010-1885 under active attack | Vulnerability | Cross-sector | Confirmed | [21] |
| 2010-07-15 | CERT/CC VU#940193; KSK-2010 root trust anchor valid from this date; Mozilla raises its bounty to USD 3,000 | Vulnerability; Defaults; Incentives | Cross-sector; internet | Confirmed | [26][73][75] |
| 2010-07-16 | Microsoft Advisory 2286198 and US-CERT alert on the shortcut flaw; Realtek certificate revoked, per Symantec | Vulnerability | Cross-sector | Confirmed | [24][23][30] |
| 2010-07-19 | Siemens investigating WinCC infections, per Symantec | State | Industrial | Confirmed | [30] |
| 2010-07 (undated) | ICS-CERT ICSA-10-201, USB Malware Targeting Siemens Control Software, names SIMATIC WinCC and STEP 7 (the page opened shows only its 2014 revision) | State | Industrial | Confirmed | [22] |
| 2010-07-22 | CVE-2010-2568 published; JMicron certificate revoked, per Symantec | Vulnerability | Cross-sector | Confirmed | [27][30] |
| 2010-07-28 | FBI, Slovenian and Spanish police announce the arrest of Mariposa's suspected creator | Crime | Consumers, finance | Confirmed | [16] |
| 2010-08-02 | Out-of-band MS10-046 fixes CVE-2010-2568, already exploited by a number of malware families | Vulnerability | Cross-sector | Confirmed | [25] |
| 2010-08-06 | Stuxnet's PLC code injection reported, per Symantec | State | Industrial | Confirmed | [30] |
| 2010-08-11 | CVE-2010-2861, ColdFusion administrator directory traversal, published | Vulnerability | Cross-sector (servers) | Confirmed | [61] |
| 2010-08-22 | Iran stops reporting new Stuxnet infections, most likely because outbound connections were blocked, per Symantec | State | Industrial | Confirmed (vendor's analysis) | [30] |
| 2010-08-23 | Microsoft Advisory 2269637 on DLL preloading ("binary planting") | Vulnerability class | Technology | Confirmed | [37] |
| 2010-08-31 | NISTIR 7628, Guidelines for Smart Grid Cyber Security, final | Standards | Energy | Confirmed | [78] |
| 2010-09-01 | Deputy Secretary Lynn's article discloses the 2008 CENTCOM compromise | State | Defense | Confirmed | [38] |
| 2010-09-07 | Siemens reports 15 Stuxnet infections worldwide with no adverse impact on the automation system | State | Industrial | Confirmed | [28] |
| 2010-09-09 | CVE-2010-2883 (Reader CoolType.dll) published; exploited in the wild in September | Vulnerability | Cross-sector | Confirmed | [62] |
| 2010-09-14 | MS10-061 fixes the Print Spooler flaw CVE-2010-2729 | Vulnerability | Cross-sector | Confirmed | [31] |
| 2010-09-17 | Microsoft Advisory 2416728, ASP.NET padding oracle CVE-2010-3332 | Vulnerability | Web | Confirmed | [39] |
| 2010-09-21 | Twitter's "onMouseOver" cross-site scripting incident | Web | Social media | Confirmed | [41] |
| 2010-09-27 | Iranian officials say Bushehr staff PCs were infected but the plant was not, as World Nuclear News relays Reuters | State | Nuclear | Reported | [35] |
| 2010-09-27 to 2010-10-01 | DHS Cyber Storm III exercise | Exercise | Government, private sector | Confirmed | [79] |
| 2010-09 | ICS-CERT ICSA-10-272-01, the Primary Stuxnet Advisory | State | Industrial | Confirmed | [29] |
| 2010-09-28 | MS10-070 fixes CVE-2010-3332 under limited, targeted attacks | Vulnerability | Web | Confirmed | [40] |
| 2010-09-30 | Symantec's Stuxnet dossier first published; SDNY charges 37 Zeus defendants; Ukraine's SBU detains five | State; Crime | Industrial; finance | Confirmed | [30][42][44] |
| 2010-10-01 | FBI announces the disruption of the Zeus theft ring (Operation Trident Breach) | Crime | Finance, municipalities | Confirmed | [43][44] |
| 2010-10-12 | October bulletins MS10-071 to MS10-086; MS10-073 fixes CVE-2010-2743, exploited by malware | Vulnerability | Cross-sector | Confirmed | [50][53] |
| 2010-10-19 | UK Strategic Defence and Security Review: GBP 650 million for a national cyber programme | Policy | Government | Confirmed | [80] |
| 2010-10-24 | Firesheep released | Web | Consumers, web | Confirmed; Demonstrated | [68] |
| 2010-10-27 | Mozilla MFSA 2010-73 for CVE-2010-3765, found during an intrusion attempt | Vulnerability | Cross-sector (browsers) | Confirmed | [56] |
| 2010-10-29 | CVE-2010-3654 (Flash, Reader authplay) published; exploited in the wild in October | Vulnerability | Cross-sector | Confirmed | [63] |
| 2010-11-03 | Microsoft Advisory 2458511, Internet Explorer CVE-2010-3962 | Vulnerability | Cross-sector (browsers) | Confirmed | [45] |
| 2010-11-09 | MS10-087 fixes six Office flaws including the RTF flaw CVE-2010-3333 | Vulnerability | Cross-sector | Confirmed | [54] |
| 2010-11 | USCC 2010 Annual Report to Congress | State; Routing | Government | Confirmed | [10] |
| 2010-11 (late) | WikiLeaks releases State Department cables; PayPal suspends its account, as later charged | Hacktivism | Payments | Confirmed (as charged) | [46] |
| 2010-11-29 | President Ahmadinejad says a worm incapacitated some centrifuges, as the Christian Science Monitor reports | State | Nuclear | Reported | [36] |
| 2010-12-03 to 2010-12-14 | CVE-2010-4398 (win32k, 3 Dec), CVE-2010-3904 (Linux RDS, 6 Dec) and CVE-2010-4344 (Exim, 14 Dec) published | Vulnerability | Cross-sector | Confirmed | [64] |
| 2010-12-06 to 2010-12-10 | Denial-of-service attacks on PayPal ("Operation Avenge Assange"), as charged. Home: [Four Books on Cybercrime](/case-studies/CYBERCRIME_FOUR_BOOKS.md) | Hacktivism | Payments | Confirmed (as charged) | [46] |
| 2010-12-08 | US Attorney's release puts Butler's cards at more than USD 87 million in fraud and more than 10,000 banks | Crime | Finance | Confirmed | [14] |
| 2010-12-14 | MS10-090 fixes CVE-2010-3962; MS10-092 fixes CVE-2010-3338; MS10-106, the year's last bulletin | Vulnerability | Cross-sector | Confirmed | [45][55][49] |
| 2011-01-18 (boundary) | Two men charged over the AT&T iPad exposure | Exposure | Telecom | Confirmed (as charged) | [20] |
| 2011-02 (boundary) | Symantec's Stuxnet dossier version 1.4; Night Dragon last seen | State | Industrial; energy | Confirmed | [30][47] |
| 2011-07-19 (boundary) | Sixteen arrested in the US over the PayPal attacks and related cases | Hacktivism | Payments | Confirmed (as charged) | [46] |
| 2012 (boundary) | Flame disclosed; ATT&CK dates it to "at least 2010" | State | Middle East | Confirmed | [48] |
| 2021-11-03 to 2026-05-20 (boundary) | KEV adds 2010 CVEs, the last two in 2026 | Vulnerability | Cross-sector | Confirmed | [8] |

## Part 2: the vulnerability record

### The Aurora flaw (summary)

The home is Part 4 of the [Zero-Day Trade](/case-studies/ZERO_DAY_MARKET_EVENTS.md) study (Confirmed [87]). Microsoft published Advisory 979352 on 14 January for the Internet Explorer HTML Object Memory Corruption flaw, and version 1.1 on 15 January revised the summary to reflect investigation of limited targeted attacks (Confirmed [3]). CERT/CC published VU#492515 the same day (Confirmed [7]). NVD and the CVE Program published CVE-2010-0249 on 15 January as a use-after-free in Internet Explorer 6, 6 SP1, 7 and 8, "as exploited in the wild in December 2009 and January 2010 during Operation Aurora", with CWE-416 and a CVSS 3.1 score of 8.8 (Confirmed [5][6]). MS10-002, a Critical cumulative update covering Internet Explorer 5.01 to 8, fixed it with seven other CVEs on 21 January; Microsoft said it was aware of limited attacks and thanked Google and Mandiant for details of limited, targeted attacks against Internet Explorer 6 customers (Confirmed [4]). KEV added CVE-2010-0249 on 20 May 2026 (Confirmed [8]).

### Exploited at or before the fix

The year's flaws for which the record shows exploitation at or before the fix, in date order:

| CVE | Product and flaw | First notice | Exploitation in the record | Fix | CWE (source) | KEV | Sources |
|---|---|---|---|---|---|---|---|
| CVE-2010-0249 | Internet Explorer, HTML object use-after-free | Advisory 979352 and VU#492515, 14 Jan | In the wild Dec 2009 and Jan 2010 during Aurora | MS10-002, 21 Jan | CWE-416 (NVD, KEV) | 2026-05-20 | [3][7][5][4][8] |
| CVE-2010-0806 | Internet Explorer | Advisory 981374 | Microsoft aware of attacks attempting to exploit it | MS10-018, 30 Mar | CWE-399 (KEV) | 2026-05-20 | [52][8] |
| CVE-2010-1297 | Flash Player, AIR, Reader and Acrobat | CVE published 8 Jun | In the wild in June | Adobe's fix not opened | CWE-787 (KEV) | 2022-06-08 | [60][8] |
| CVE-2010-1885 | Windows Help and Support Center | Advisory 2219475 | Microsoft aware of active attacks | MS10-042, 13 Jul | not checked | not in KEV | [21] |
| CVE-2010-2568 | Windows Shell shortcut icon loading | Advisory 2286198 and US-CERT alert, 16 Jul; VU#940193, 15 Jul | Demonstrated in the wild in July; exploited by a number of malware families at MS10-046's release | MS10-046, 2 Aug (out of band) | CWE-20 (KEV); NVD-CWE-noinfo (NVD) | 2022-09-15 | [24][23][26][27][25][8] |
| CVE-2010-2883 | Adobe Reader CoolType.dll stack overflow | CVE published 9 Sep | In the wild in September | Adobe's fix not opened | CWE-119 (KEV); CWE-787 (CISA ADP in the CVE record) | 2022-06-08 | [62][8] |
| CVE-2010-2729 | Windows Print Spooler | MS10-061, 14 Sep | Exploited on a limited scale by malware at release; in the wild in September per the CVE record | MS10-061, 14 Sep | CWE-20 (NVD) | not in KEV | [31][32] |
| CVE-2010-3332 | ASP.NET padding oracle | Advisory 2416728, 17 Sep | Limited, targeted attacks | MS10-070, 28 Sep | not checked | not in KEV | [39][40] |
| CVE-2010-2743 | Win32k keyboard layout | MS10-073, 12 Oct | Stuxnet demonstrated it in July; exploited on a limited scale by malware at release | MS10-073, 12 Oct | not checked | not in KEV | [32][53] |
| CVE-2010-3765 | Firefox 3.6 on Windows XP | MFSA 2010-73, 27 Oct | Found by Telenor SOC investigating an intrusion attempt; exploited by the Belmoo malware in October | Firefox 3.5.15 and 3.6.12 | not checked | 2025-10-06 | [56][57][8] |
| CVE-2010-3654 | Flash Player and Reader's authplay component | CVE published 29 Oct | In the wild in October | Adobe's fix not opened | not checked | not in KEV | [63] |
| CVE-2010-3962 | Internet Explorer, uninitialized memory | Advisory 2458511, 3 Nov | MS10-090 calls it the vulnerability "currently being exploited" | MS10-090, 14 Dec | not checked | 2025-10-06 | [45][8] |
| CVE-2010-3338 | Windows Task Scheduler | MS10-092, 14 Dec | Limited, targeted attacks | MS10-092, 14 Dec | CWE-20 (NVD) | not in KEV | [55][32] |

Three more flaws are in KEV without an exploitation date in the sources opened here. CVE-2010-0188 in Adobe Reader and Acrobat before 9.3.1 was published on 21 February, and KEV lists it with CWE-94 and flags known ransomware use (Confirmed [58][8]). MS10-087 fixed six Office flaws on 9 November, including the RTF flaw CVE-2010-3333, which NVD published on 10 November with CWE-787 and KEV lists with CWE-119 (Confirmed [54][65][8]). MS10-015 fixed the publicly disclosed kernel flaw CVE-2010-0232 on 9 February with no exploitation known at release; KEV added it on 3 March 2022 (Confirmed [51][8]).

In ATT&CK terms the browser, document and plug-in flaws read as T1203 Exploitation for Client Execution, and the privilege-escalation flaws as T1068 Exploitation for Privilege Escalation; ATT&CK lists T1203 for Elderwood and T1068 for Stuxnet, but tying either to the other 2010 flaws is this study's reading (Confirmed [11][34]; Inferred).

### Servers and middleware

Three flaws published in 2010 sat in internet-facing server software and one in the Linux kernel. CVE-2010-0738, published on 28 April, is the JBoss JMX-Console applying access control only to the GET and POST methods (Confirmed [59]). CVE-2010-2861, published on 11 August, is directory traversal in the Adobe ColdFusion administrator console, 9.0.1 and earlier, listed by KEV as CWE-22 (Confirmed [61][8]). CVE-2010-4344, published on 14 December, is a heap overflow in Exim before 4.70, and CVE-2010-3904, published on 6 December, is a Linux RDS local privilege escalation (Confirmed [64]). KEV lists all four, and flags CVE-2010-0738, CVE-2010-1428 (also JBoss), CVE-2010-2861 and CVE-2010-0188 for known ransomware use (Confirmed [8]). The record opened here gives no 2010 exploitation date for the server flaws, so this study does not date their abuse to 2010 (Inferred).

### Classes of flaw: DLL preloading and the padding oracle

Microsoft Security Advisory 2269637 of 23 August addressed published research on a remote attack vector for a class of insecure library loading flaws, which it calls binary planting or DLL preloading, caused by applications loading libraries from insufficiently qualified paths (Confirmed [37]). The advisory is about a class, not one product, and gave guidance to developers (Confirmed [37]). ATT&CK's T1574.001 DLL is this study's mapping (Inferred). Advisory 2416728, published 17 September and updated 28 September, covered the ASP.NET padding oracle CVE-2010-3332, and MS10-070 of 28 September fixed it, with Microsoft aware of limited, targeted attacks (Confirmed [39][40]).

### Microsoft's year in bulletins

MS10-001 was published on 12 January and MS10-106 on 14 December, and MS10-107 does not exist, so the year carried 106 bulletins by numbering (Confirmed [49]; the count is Inferred). All sixteen October bulletins, MS10-071 to MS10-086, were published on 12 October and carry 49 distinct vulnerability sections, counted from the individual bulletin pages because the monthly summary page would not open (Confirmed [50]; the count is Inferred).

### The KEV tail

The KEV catalog, version 2026.11.10, lists 23 CVE-2010 entries (Confirmed [8]; Demonstrated). Their dates added run from 3 November 2021 to 20 May 2026 (Confirmed [8]):

| KEV dateAdded | CVE-2010 ids |
|---|---|
| 2021-11-03 | CVE-2010-5326 |
| 2021-12-10 | CVE-2010-1871 |
| 2022-03-03 | CVE-2010-3333, CVE-2010-0232, CVE-2010-0188 |
| 2022-03-25 | CVE-2010-4344, CVE-2010-4345, CVE-2010-2861, CVE-2010-3035 |
| 2022-03-28 | CVE-2010-4398 |
| 2022-04-15 | CVE-2010-5330 |
| 2022-05-25 | CVE-2010-0840, CVE-2010-0738, CVE-2010-1428 |
| 2022-06-08 | CVE-2010-2883, CVE-2010-2572, CVE-2010-1297 |
| 2022-09-15 | CVE-2010-2568 |
| 2023-05-12 | CVE-2010-3904 |
| 2025-10-06 | CVE-2010-3962, CVE-2010-3765 |
| 2026-05-20 | CVE-2010-0249, CVE-2010-0806 |

The gap between exploitation and listing runs to 16 years, so a KEV date says when CISA added the flaw to the catalog, not when it was exploited (Inferred [8][5]).

## Part 3: Stuxnet in 2010 (summary)

The [Stuxnet](/case-studies/STUXNET.md) study is the home, and it already carries ICSA-10-201-01C, ICSA-10-272-01, MS10-046, MS10-061 and the Symantec dossier (Confirmed [87]). Symantec's W32.Stuxnet Dossier, first published on 30 September (version 1.4 of February 2011 opened), dates the year: VirusBlokAda reported the malware on 17 June; Microsoft's Advisory 2286198 and the revocation of the Realtek certificate came on 16 July; Siemens was investigating WinCC infections on 19 July; the JMicron certificate was revoked on 22 July; MS10-046 shipped on 2 August; PLC code injection was reported on 6 August; and MS10-061 shipped on 14 September (Confirmed [30]). Symantec counted about 100,000 infected hosts and more than 40,000 external IP addresses in over 155 countries, roughly 60 percent of infected hosts in Iran; targeted organizations, all with a presence in Iran, were attacked in June and July 2009 and March, April and May 2010; and from 22 August Iran stopped reporting new infections, most likely because outbound connections to the command servers were blocked (Confirmed [30]). Symantec cautions readers against drawing attribution conclusions, and the 2010 primaries opened here name no sponsoring state (Confirmed [30]).

The defender record ran in parallel. CERT/CC's VU#940193 gives 10 July as the date the shortcut flaw became public and 15 July as its first publication (Confirmed [26]). US-CERT's alert of 16 July said that viewing a crafted shortcut's location in Windows Explorer was enough to run code, that AutoRun or AutoPlay on removable drives could trigger it without interaction, and that a malicious website or WebDAV share could also reach it (Confirmed [23]). ICS-CERT's ICSA-10-201-01C said the trojan interacts with Siemens SIMATIC WinCC or STEP 7 and queries SIMATIC databases, reported four infected Siemens customers with no production impact, and recommended disabling shortcut icons, WebClient and AutoRun, least privilege, current antivirus, caution with USB drives and the Siemens update (Confirmed [22]). ICSA-10-238-01B said Stuxnet used five vulnerabilities, MS08-067 and four zero-days, spread by USB, network shares and SQL databases, and carried a kernel-mode rootkit signed with two revoked certificates, and that on 7 September Siemens reported 15 infections worldwide with no adverse impact on the automation system (Confirmed [28]). The Primary Stuxnet Advisory, ICSA-10-272-01, added propagation through STEP 7 project files, WinCC database files and the print spooler flaw fixed by MS10-061, with updates through command and control and peer-to-peer RPC (Confirmed [29]). NVD records CVE-2010-2772, a hard-coded password in Siemens WinCC and PCS 7 (CWE-798), as demonstrated in the wild in July 2010 by Stuxnet (Confirmed [33]). MS10-061 itself does not name Stuxnet (Confirmed [31]).

In Iran, officials said that Bushehr staff computers were infected but the plant was not affected, as World Nuclear News relayed from Reuters on 27 September, and on 29 November President Ahmadinejad said a computer worm had incapacitated some centrifuges, without naming Stuxnet, as the Christian Science Monitor reported (Reported [35][36]). ATT&CK's S0603 Stuxnet was discovered in 2010 with some components used as early as November 2008, is the first publicly reported malware to target ICS devices specifically, and lists no group (Confirmed [34]).

## Part 4: the crime record

### Max Butler and the 2010 records (summary)

The home is [Four Books on Cybercrime](/case-studies/CYBERCRIME_FOUR_BOOKS.md) (Confirmed [87]). On 12 February Max Ray Butler, known as "Iceman", was sentenced in the Western District of Pennsylvania to 13 years in prison, five years of supervised release and USD 27.5 million in restitution for wire fraud; he hacked financial institutions and card processing centres and co-ran CardersMarket, which had about 4,500 members at its peak, and more than 1.8 million stolen card numbers were found on his systems (Confirmed [13]). A US Attorney's release of 8 December says the cards carried more than USD 87 million in fraudulent charges and affected more than 10,000 US banks (Confirmed [14]).

### Gonzalez and the TJX ring (summary)

The home for Heartland and the Gonzalez ring is [E-Commerce Threats](/case-studies/ECOMMERCE_THREATS.md) (Confirmed [87]). A US Attorney's release of 16 April in the District of Massachusetts records that Albert Gonzalez was sentenced on 25 March to 20 years plus three years of supervised release, that co-conspirator Damon Patrick Toey was sentenced to five years and a USD 100,000 fine, and that 40 million distinct card numbers sat on two conspirators' servers (Confirmed [66]). On 29 March Christopher Scott, whose role was wardriving into retailers' wireless networks in Miami from about 2003 to 2007, was sentenced to seven years (Confirmed [67]). The home study also records the 8 January Heartland and Visa settlement of up to USD 60 million for Visa issuers; the SEC exhibit was not reopened for this study (Inferred [82][87]).

### Waledac: a civil takedown

On 24 February Microsoft announced "Operation b49": on 22 February a judge in the Eastern District of Virginia had granted a temporary restraining order in Microsoft v. John Does 1-27 (civil action 1:10CV156) that cut off 277 domains of the Waledac spam botnet (Confirmed as the plaintiff's account [15]). Microsoft estimated that Waledac could send more than 1.5 billion spam e-mails a day, that about 651 million Waledac spam e-mails reached Hotmail between 3 and 21 December 2009, and that hundreds of thousands of computers were infected; these are the company's own estimates (Reported [15]). The library's ATT&CK data has no Waledac object (Demonstrated [84]).

### Mariposa

The FBI, the Slovenian Criminal Police and the Spanish Guardia Civil announced on 28 July that the Guardia Civil had arrested three suspected Mariposa operators in February and that Slovenian police had arrested the suspected creator, "Iserdo", 23, the week before (Confirmed [16]). The botnet was built with the Butterfly Bot kit, which was sold to hundreds of criminals, and was used to steal passwords and card data and to launch denial-of-service attacks (Confirmed [16]). Industry experts estimated that Mariposa may have infected 8 to 12 million computers; the FBI quotes the figure as an estimate, not a count (Reported [16]).

### Zeus and Operation Trident Breach

On 30 September the US Attorney for the Southern District of New York charged 37 defendants in 21 cases over global bank fraud schemes that used the Zeus Trojan and other malware (Confirmed as charged [42]). As charged, Zeus arrived as an apparently benign e-mail at small businesses and municipalities, recorded keystrokes at online-banking login, and the stolen credentials funded unauthorized transfers to hundreds of false-name accounts run by a money mule organization that recruited mules on student visas; more than USD 3 million moved from dozens of compromised accounts (Confirmed as charged [42]). The FBI said on 1 October that Operation Trident Breach had begun in May 2009 when Omaha agents saw ACH payments to 46 accounts, that the ring had stolen USD 70 million and attempted about USD 220 million from medium-sized companies, towns and churches, that partners were in the Netherlands, Ukraine and the UK, that Ukraine's SBU detained five people on 30 September, and that its New York office had arrested 10 people and was seeking 17 others (Confirmed [43][44]). The library's S0016 P2P ZeuS is Gameover ZeuS, a later variant, so this study binds no Zeus software object (Demonstrated [84]).

### The AT&T iPad exposure

Per the District of New Jersey complaint unsealed on 18 January 2011, a script that mimicked an iPad 3G guessed ICC-IDs against an AT&T web service from 5 to 9 June 2010 and harvested about 120,000 ICC-ID and e-mail pairs; the data went to Gawker, which published redacted results; a group calling itself Goatse Security was identified; and two men were charged with conspiracy to access AT&T's servers (Confirmed as charged [20]). The complaint as summarized names no software flaw, so this study binds no ATT&CK technique to it (Inferred).

### Operation Avenge Assange (summary)

The home is [Four Books on Cybercrime](/case-studies/CYBERCRIME_FOUR_BOOKS.md) (Confirmed [87]). According to a DOJ and FBI release of 19 July 2011, WikiLeaks released State Department cables in late November 2010, PayPal suspended its account, and the San Jose indictment alleges that Anonymous ran denial-of-service attacks on PayPal from 6 to 10 December 2010, which it called "Operation Avenge Assange", with a free open-source tool; 14 people were arrested on that indictment and two more on related complaints, more than 35 search warrants were executed, and UK and Dutch police made one and four arrests (Confirmed as charged [46]).

## Part 5: the state and espionage record

### Operation Aurora (summary)

The home is the [Zero-Day Trade](/case-studies/ZERO_DAY_MARKET_EVENTS.md) study (Confirmed [87]); the actor view is in [China-attributed threat actors](/case-studies/THREAT_ACTORS_CHINA.md). Google's post of 12 January says the attack originated from China and resulted in theft of intellectual property, that at least twenty other large companies were targeted, that a primary goal appeared to be the Gmail accounts of Chinese human rights activists, and that only two accounts appear to have been accessed, limited to account information and subject lines; it does not name the Chinese government, and it advised antivirus, patching and browser updates (Confirmed [1]). On 22 March Google stopped censoring Search, News and Images on Google.cn and redirected users to Google.com.hk, citing the January attacks and the surveillance they uncovered (Confirmed [2]). The Secretary of State's remarks of 21 January said the United States looked to Chinese authorities to conduct a thorough review of the intrusions that led to Google's announcement (Confirmed [9]).

The USCC's 2010 Annual Report says the breach appeared to originate within China and targeted other US companies, and assesses that such efforts likely operate with the tacit knowledge of the Chinese government and may even involve full government support; that is the Commission's assessment, not a finding (Confirmed [10]). The same report quotes iDefense as saying the source IP addresses and servers corresponded to a single foreign entity of Chinese state agents or proxies, says researchers traced the penetration to two schools in China, one with military ties, and, citing Google's information security manager, says the attackers profiled targeted employees on social networks, posed as an acquaintance in a chat session, and got an employee to click a link to a malicious photo-sharing site, reportedly hosted in Taiwan, that downloaded malware (Reported [10]).

ATT&CK describes G0066 Elderwood, aliases Elderwood Gang, Beijing Group and Sneaky Panda, as a suspected Chinese espionage group "reportedly responsible" for the 2009 Google intrusion, and S0203 Hydraq, whose aliases include Aurora and 9002 RAT, as first used by Elderwood in that intrusion and associated with Elderwood and Axiom (G0001) (Confirmed that ATT&CK says so [11][12]; the attribution is Reported). Elderwood's techniques come from reporting across 2009 to 2012 and are not specific to Aurora (Confirmed [11]). The library's [Notable Incidents](/NOTABLE_INCIDENTS.md) table attributes Aurora to "APT10 / Comment Crew (Chinese PLA Unit 61398, attributed)", which the [Hacker and the State](/case-studies/HACKER_AND_THE_STATE_CASES.md) study already flags as merging distinct groups; this chronicle uses G0066 as ATT&CK maps it and does not repeat that line (Inferred [87][11]).

### Shadows in the Cloud

The Information Warfare Monitor (Citizen Lab and SecDev) and the Shadowserver Foundation published "Shadows in the Cloud: Investigating Cyber Espionage 2.0", JR03-2010, on 6 April, after an eight-month investigation; a Citizen Lab op-ed of 7 April confirmed the release and noted that at least one Canadian institution was ensnared (Confirmed [18][19]). The network compromised government, business and academic systems in India, including its national security establishment, the Offices of the Dalai Lama and the United Nations; the Embassy of Pakistan in the United States was also compromised (Confirmed [18]). The recovered data included Indian government documents, two marked SECRET, six RESTRICTED and five CONFIDENTIAL, possibly taken from personal computers; 1,500 letters sent from the Dalai Lama's office between January and November 2009; and visa applications to Indian missions in Afghanistan from nationals of 13 countries (Confirmed [18]). Command and control used Twitter, Google Groups, Blogspot, Baidu Blogs, blog.com and Yahoo Mail as a top tier, falling back to core servers in the PRC (Confirmed [18]).

On attribution the report says the attackers' identity and motivation remain unknown, places them in Chengdu only through circumstantial evidence, links two Chengdu individuals to the PRC underground hacking community, and recalls that the GhostNet investigation found too little evidence to implicate the Chinese government (Confirmed [18]; the Chengdu location is the researchers' assessment, Reported). ATT&CK has no object for this network, so no group or software id is bound; T1102 Web Service is this study's mapping of the layered command and control (no ATT&CK object: Demonstrated [84]; the T1102 mapping: Inferred from [18]).

### The China Telecom route event

The USCC's 2010 Annual Report says that for about 18 minutes on 8 April China Telecom advertised erroneous routes that sent traffic for about 15 percent of internet destinations through Chinese servers, affecting .gov and .mil sites, among them the Senate, the Army, Navy, Marine Corps and Air Force, the Office of the Secretary of Defense, NASA, Commerce and NOAA, and commercial sites including Dell, Yahoo, Microsoft and IBM (Confirmed [10]). It says the erroneous data appear to have originated at IDC China Telecommunication and that it has no way to determine what, if anything, Chinese telecommunications firms did with the traffic (Confirmed [10]). The report makes no finding of intent, and no ATT&CK object or technique binds cleanly, so this study binds none (Confirmed [10]; Inferred).

### Night Dragon

ATT&CK's campaign [C0002 Night Dragon](/mitre/campaigns/C0002.md) targeted oil, energy and petrochemical companies and individuals in Kazakhstan, Taiwan, Greece and the United States, first seen in November 2009 and last seen in February 2011, so 2010 is its only full year (Confirmed [47]). The actors are unidentified and researchers assessed a China-based group; ATT&CK lists 29 techniques and the software ASPXSpy (S0073), at (S0110), gsecdump (S0008), PsExec (S0029) and zwShell (S0350) (Confirmed [47]; Demonstrated [84]). The [China-attributed threat actors](/case-studies/THREAT_ACTORS_CHINA.md) study carries Night Dragon in its campaign table (Confirmed [87]).

### Buckshot Yankee, disclosed

Deputy Secretary of Defense William J. Lynn III wrote in Foreign Affairs, published on 1 September, that in 2008 an infected flash drive inserted into a US military laptop at a base in the Middle East, carrying code placed by a foreign intelligence agency, spread across Central Command's classified and unclassified systems (Confirmed [38]). He called it the most significant breach of US military computers ever and named the response Operation Buckshot Yankee (Confirmed [38]). The event is 2008; 2010 is the disclosure (Confirmed [38]).

### Written later: Flame and Operation Dust Storm

ATT&CK's [S0143 Flame](/mitre/software/S0143.md) is an information-collection toolkit active since at least 2010 that primarily targeted Middle Eastern countries, with no group listed; it was disclosed in 2012 (Confirmed [48]); the [United States-attributed threat actors](/case-studies/THREAT_ACTORS_UNITED_STATES.md) study carries its technical record. The library's ATT&CK data gives campaign [C0016 Operation Dust Storm](/mitre/campaigns/C0016.md) a first-seen date of January 2010 and a last-seen date of February 2016 (Demonstrated [84]). Neither was known in 2010, so neither is in this study's Navigator layer (Inferred).

## Part 6: the web, trust and defaults

### Apache's JIRA attack

The Apache Software Foundation reported on 13 April a direct, targeted attack on its JIRA host, brutus.apache.org, from 5 to 9 April (Confirmed [17]). As Apache describes it, a cross-site scripting link posted in a new issue stole administrators' sessions; a parallel brute-force attack on the login page succeeded on 6 April; the attackers changed the attachment storage path so that JSP files would run; they copied home directories; and by 9 April they had installed a component that captured passwords (Confirmed [17]). The hashed passwords of JIRA, Bugzilla and Confluence users were compromised (Confirmed [17]). In ATT&CK terms this is T1539 Steal Web Session Cookie and T1110 Brute Force (basis Described), with T1505.003 Web Shell for the JSP step (basis Inferred); the mapping is this study's (Inferred from [17]).

### Twitter's onMouseOver incident

Twitter wrote on 21 September that it was notified at 2:54 am PDT of a cross-site scripting exploit that had surfaced about half an hour earlier, and that it fixed the primary issue by 7:00 am PDT (Confirmed [41]). The flaw had been patched the month before and was resurfaced by an unrelated site update (Confirmed [41]). CWE-79 and CAPEC-63 are this study's pairing (Inferred).

### Firesheep and encryption by default

On 12 January Gmail began turning HTTPS on by default for all users; the option had existed since 2008 (Confirmed [76]). On 17 June EFF and the Tor Project released HTTPS Everywhere, a Firefox extension that moved connections to sites such as Google Search, Wikipedia, Twitter and Facebook onto HTTPS (Confirmed [77]). On 24 October Eric Butler released Firesheep, which showed that anyone on an open wireless network could capture unencrypted session cookies and take over nearby users' accounts ("sidejacking"); its author argued that only full end-to-end HTTPS fixes this (Confirmed as the author's post [68]; Demonstrated by the tool). T1539 Steal Web Session Cookie, T1550.004 Web Session Cookie and T1040 Network Sniffing are this study's mapping; ATT&CK does not cite Firesheep (Inferred).

### The protocol and the root

RFC 5746, the TLS Renegotiation Indication Extension, was published as a Proposed Standard in February; it binds each renegotiation to its enclosing connection so an attacker cannot prefix traffic to a client's session (Confirmed [70]). The first DNS root trust anchor, KSK-2010 with key tag 19036, is valid from 15 July 2010 to 11 January 2019 in IANA's root-anchors file, which marks when the signed root became verifiable (Confirmed [73]).

### Paying for bugs

The Chromium project announced a vulnerability reward program on 28 January, with a USD 500 base reward and USD 1,337 for especially severe or clever bugs, crediting Mozilla's long-running program (Confirmed [74]). Mozilla raised its bounty to USD 3,000 per eligible bug for reports from 1 July, announced on 15 July, and added Firefox Mobile and the Mozilla services those products rely on (Confirmed [75]). The [Zero-Day Trade](/case-studies/ZERO_DAY_MARKET_EVENTS.md) study reads Google's reward programs as following Aurora; that reading is the home study's (Inferred [87]).

## Part 7: law, policy and standards

### Organizing for cyber

Deputy Secretary Lynn wrote that US Cyber Command, ordered by Secretary Gates in June 2009, began operations in May 2010 under US Strategic Command, was slated to be fully operational by October, and would integrate cyberdefense operations (Confirmed [38]). DHS's Cyber Storm III ran from 27 September to 1 October with 8 Cabinet-level departments, 13 states, 12 international partners and about 60 private-sector companies; it tested the National Cyber Incident Response Plan and the NCCIC, and no actual networks were targeted (Confirmed [79]). The UK's Strategic Defence and Security Review, published on 19 October, set up a transformative national programme to protect the UK in cyberspace backed by GBP 650 million of new funds (Confirmed [80]). The Obama White House archive publishes a summary page for the CNCI, the federal cybersecurity initiative, starting with Initiative 1, Trusted Internet Connections; the page carries no date, and its 2010 declassification date was not checked (Confirmed [81]; not checked).

### Standards and frameworks

NIST published SP 800-37 Revision 1, Guide for Applying the Risk Management Framework to Federal Information Systems: A Security Life Cycle Approach, in February 2010; it was updated on 5 June 2014, withdrawn on 20 December 2019 and superseded by Revision 2 (Confirmed [69]). NIST published NISTIR 7628, Guidelines for Smart Grid Cyber Security, in final form on 31 August 2010; it was withdrawn on 25 September 2014 and superseded by Revision 1 (Confirmed [78]). The 2010 CWE/SANS Top 25 is dated 29 March, and its top five are CWE-79 (cross-site scripting), CWE-89 (SQL injection), CWE-120 (classic buffer overflow), CWE-352 (cross-site request forgery) and CWE-285 (improper authorization) (Confirmed [71]). The OWASP Top 10 2010 puts Injection at A1 and cross-site scripting at A2, adds Security Misconfiguration at A6, debuts Unvalidated Redirects and Forwards at A10, and places Insufficient Transport Layer Protection at A9; the document says the Top 10 was first released in 2003 with minor updates in 2004 and 2007 (Confirmed [72]). Its release day, 19 April, is taken from the PDF's creation metadata and is approximate (Confirmed [72]).

## Part 8: the defender view

**Removable media needed a policy, not a default.** The shortcut flaw ran code from a drive viewed in a file manager, and AutoRun or AutoPlay could trigger it without interaction (Confirmed [23][22]). Disabling AutoRun and restricting removable media are ATT&CK mitigations in substance: [M1042 Disable or Remove Feature or Program](/mitre/mitigations/M1042.md) and [M1034 Limit Hardware Installation](/mitre/mitigations/M1034.md) (Inferred).

**Workarounds bought time.** The shortcut flaw had no fix for at least the 17 days between Advisory 2286198 and MS10-046; the workarounds MS10-046 records were to disable shortcut icon display and the WebClient service and to block LNK and PIF files at the gateway and outbound SMB at the perimeter, and ICS-CERT added disabling AutoRun (Confirmed [25][24][22]; Inferred for the count). The [vulnerability management reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md) covers working from advisories as well as bulletins (Inferred).

**Signed was not safe.** Stuxnet's drivers were signed with two certificates that had to be revoked in July (Confirmed [28][30]). [Certificate Analysis](/mitre/d3fend/certificate-analysis.md) is the matching D3FEND page; the library links no countermeasure to T1553.002 (Demonstrated [85]; Inferred for the pairing).

**Default credentials were an industrial weakness.** The hard-coded WinCC password was in the field when Stuxnet used it (Confirmed [33]). [Change Default Password](/mitre/d3fend/change-default-password.md) is the countermeasure the library links to T1078.001 (Demonstrated [85]).

**Encryption had to cover the session, not just the login.** Firesheep took cookies from sites that encrypted only the login, and Gmail and HTTPS Everywhere moved whole sessions to HTTPS (Confirmed [68][76][77]). [M1041 Encrypt Sensitive Information](/mitre/mitigations/M1041.md) and [Message Encryption](/mitre/d3fend/message-encryption.md) are the matching controls (Inferred).

**Fraud detection needed the bank's side.** Zeus captured credentials at the customer's keyboard and the theft surfaced as ACH payments to mule accounts, which is how Omaha agents first saw it (Confirmed [42][44]). [M1032 Multi-factor Authentication](/mitre/mitigations/M1032.md) and [M1017 User Training](/mitre/mitigations/M1017.md) are the matching mitigations (Inferred).

**Takedown was a legal tool.** Waledac was cut off by a civil restraining order, and Mariposa's suspected operators and creator were arrested in two countries (Confirmed [15][16]). The [incident response reference](/INCIDENT_RESPONSE_REFERENCE.md) carries the coordination side (Inferred).

**Collaboration tools were targets.** Apache's issue tracker gave the attackers a cross-site scripting link and a login page to brute-force, and an admin path to run code (Confirmed [17]). [M1036 Account Use Policies](/mitre/mitigations/M1036.md), [M1032 Multi-factor Authentication](/mitre/mitigations/M1032.md) and [M1048 Application Isolation and Sandboxing](/mitre/mitigations/M1048.md) are the matching mitigations (Inferred).

## Part 9: MITRE mappings

No 2010 record opened here carries an ATT&CK id; every binding below is a later mapping (Inferred [5][11]). Every Enterprise binding is either a technique ATT&CK lists for an object it ties to 2010 (G0066 Elderwood, S0203 Hydraq, C0002 Night Dragon, S0603 Stuxnet) or this study's mapping of a behavior a source describes (Inferred). Every id was checked against the library's data files (`data/attack/technique_profiles.jsonl`, `software_to_technique.jsonl`, `group_to_technique.jsonl`, `campaign_profiles.jsonl`, `groups.jsonl`, `software.jsonl`, `technique_to_d3fend.jsonl`, `data/attack/ics/` and `data/weaknesses/`) and against the generated pages under `mitre/` on 12 and 13 November 2026 (Demonstrated [84][85][86]). Names and tactics are those of ATT&CK v20.0 as the library carries them, including the v20.0 tactics stealth and defense-impairment (Demonstrated [84]).

The Basis column says how strong each tie is, as in the [2016 chronicle](/case-studies/CHRONICLE_2016.md). **Listed** means ATT&CK itself lists the id for the object. **Described** means a primary source describes the behavior and this study assigns the id. **Reported** means only a Reported source describes it. **Inferred** means the mapping rests on this study's reading. Two caveats apply to the Listed rows: Elderwood's and Hydraq's tie to Aurora is ATT&CK's "reportedly" and "first used", with techniques drawn from reporting across 2009 to 2012, and only the Stuxnet techniques that a 2010 primary describes are listed here; the [Stuxnet](/case-studies/STUXNET.md) study carries all 44 (Confirmed [11][12][34]; Demonstrated [84]).

### ATT&CK Enterprise techniques

| Id | Name (ATT&CK v20.0) | Tactic(s) | Basis | Dated event or report | Sources |
|---|---|---|---|---|---|
| [`T1189`](/mitre/techniques/T1189.md) | Drive-by Compromise | initial-access | Listed (G0066) | Elderwood, reportedly Aurora (disclosed 12 Jan); the USCC's account of a link to a malicious photo-sharing site (Nov; Reported) | [11][10] |
| [`T1203`](/mitre/techniques/T1203.md) | Exploitation for Client Execution | execution | Listed (G0066); Described | CVE-2010-0249 in limited, targeted attacks (MS10-002, 21 Jan); Internet Explorer, Firefox, Reader, Flash and Office flaws exploited at or before their fixes (Jan to Dec; match Inferred) | [11][4][52][56][60][62][63][45] |
| [`T1105`](/mitre/techniques/T1105.md) | Ingress Tool Transfer | command-and-control | Listed (G0066, S0203, C0002); Described | Elderwood, Hydraq, Night Dragon; the Aurora link downloaded malware (USCC; Reported) | [11][12][47][10] |
| [`T1027.002`](/mitre/techniques/T1027-002.md) | Software Packing | stealth | Listed (G0066, C0002) | Elderwood; Night Dragon (ATT&CK objects) | [11][47] |
| [`T1027.013`](/mitre/techniques/T1027-013.md) | Encrypted/Encoded File | stealth | Listed (G0066, C0002) | Elderwood; Night Dragon (ATT&CK objects) | [11][47] |
| [`T1566.001`](/mitre/techniques/T1566-001.md) | Spearphishing Attachment | initial-access | Listed (G0066) | Elderwood (ATT&CK object) | [11] |
| [`T1566.002`](/mitre/techniques/T1566-002.md) | Spearphishing Link | initial-access | Listed (G0066, C0002) | Elderwood; Night Dragon | [11][47] |
| [`T1204.001`](/mitre/techniques/T1204-001.md) | Malicious Link | execution | Listed (G0066, C0002) | Elderwood; Night Dragon; the Aurora employee clicked a link (USCC; Reported) | [11][47][10] |
| [`T1204.002`](/mitre/techniques/T1204-002.md) | Malicious File | execution | Listed (G0066) | Elderwood (ATT&CK object) | [11] |
| [`T1005`](/mitre/techniques/T1005.md) | Data from Local System | collection | Listed (S0203, C0002); Described | Hydraq; Night Dragon; Apache attackers copied home directories (5 to 9 Apr) | [12][47][17] |
| [`T1007`](/mitre/techniques/T1007.md) | System Service Discovery | discovery | Listed (S0203) | Hydraq (ATT&CK object) | [12] |
| [`T1012`](/mitre/techniques/T1012.md) | Query Registry | discovery | Listed (S0203) | Hydraq (ATT&CK object) | [12] |
| [`T1016`](/mitre/techniques/T1016.md) | System Network Configuration Discovery | discovery | Listed (S0203) | Hydraq (ATT&CK object) | [12] |
| [`T1027`](/mitre/techniques/T1027.md) | Obfuscated Files or Information | stealth | Listed (S0203) | Hydraq (ATT&CK object) | [12] |
| [`T1048`](/mitre/techniques/T1048.md) | Exfiltration Over Alternative Protocol | exfiltration | Listed (S0203) | Hydraq (ATT&CK object) | [12] |
| [`T1057`](/mitre/techniques/T1057.md) | Process Discovery | discovery | Listed (S0203) | Hydraq (ATT&CK object) | [12] |
| [`T1070.004`](/mitre/techniques/T1070-004.md) | File Deletion | stealth | Listed (S0203) | Hydraq (ATT&CK object) | [12] |
| [`T1082`](/mitre/techniques/T1082.md) | System Information Discovery | discovery | Listed (S0203) | Hydraq (ATT&CK object) | [12] |
| [`T1083`](/mitre/techniques/T1083.md) | File and Directory Discovery | discovery | Listed (S0203, C0002) | Hydraq; Night Dragon | [12][47] |
| [`T1112`](/mitre/techniques/T1112.md) | Modify Registry | defense-impairment, persistence | Listed (S0203, C0002) | Hydraq; Night Dragon | [12][47] |
| [`T1113`](/mitre/techniques/T1113.md) | Screen Capture | collection | Listed (S0203) | Hydraq (ATT&CK object) | [12] |
| [`T1129`](/mitre/techniques/T1129.md) | Shared Modules | execution | Listed (S0203) | Hydraq (ATT&CK object) | [12] |
| [`T1134`](/mitre/techniques/T1134.md) | Access Token Manipulation | stealth, privilege-escalation | Listed (S0203) | Hydraq (ATT&CK object) | [12] |
| [`T1543.003`](/mitre/techniques/T1543-003.md) | Windows Service | persistence, privilege-escalation | Listed (S0203) | Hydraq (ATT&CK object) | [12] |
| [`T1569.002`](/mitre/techniques/T1569-002.md) | Service Execution | execution | Listed (S0203) | Hydraq (ATT&CK object) | [12] |
| [`T1573.001`](/mitre/techniques/T1573-001.md) | Symmetric Cryptography | command-and-control | Listed (S0203) | Hydraq (ATT&CK object) | [12] |
| [`T1685.005`](/mitre/techniques/T1685-005.md) | Clear Windows Event Logs | defense-impairment | Listed (S0203) | Hydraq (ATT&CK object) | [12] |
| [`T1003.002`](/mitre/techniques/T1003-002.md) | Security Account Manager | credential-access | Listed (C0002) | Night Dragon (Nov 2009 to Feb 2011) | [47] |
| [`T1008`](/mitre/techniques/T1008.md) | Fallback Channels | command-and-control | Listed (C0002) | Night Dragon | [47] |
| [`T1033`](/mitre/techniques/T1033.md) | System Owner/User Discovery | discovery | Listed (C0002) | Night Dragon | [47] |
| [`T1059.003`](/mitre/techniques/T1059-003.md) | Windows Command Shell | execution | Listed (C0002) | Night Dragon | [47] |
| [`T1071.001`](/mitre/techniques/T1071-001.md) | Web Protocols | command-and-control | Listed (C0002) | Night Dragon | [47] |
| [`T1074.002`](/mitre/techniques/T1074-002.md) | Remote Data Staging | collection | Listed (C0002) | Night Dragon | [47] |
| [`T1078`](/mitre/techniques/T1078.md) | Valid Accounts | stealth, persistence, privilege-escalation, initial-access | Listed (C0002) | Night Dragon | [47] |
| [`T1078.002`](/mitre/techniques/T1078-002.md) | Domain Accounts | stealth, persistence, privilege-escalation, initial-access | Listed (C0002) | Night Dragon | [47] |
| [`T1110.002`](/mitre/techniques/T1110-002.md) | Password Cracking | credential-access | Listed (C0002) | Night Dragon | [47] |
| [`T1114.001`](/mitre/techniques/T1114-001.md) | Local Email Collection | collection | Listed (C0002) | Night Dragon | [47] |
| [`T1133`](/mitre/techniques/T1133.md) | External Remote Services | persistence, initial-access | Listed (C0002) | Night Dragon | [47] |
| [`T1190`](/mitre/techniques/T1190.md) | Exploit Public-Facing Application | initial-access | Listed (C0002); Described | Night Dragon; ASP.NET padding oracle CVE-2010-3332 under limited, targeted attacks (Sep); JBoss, ColdFusion and Exim flaws in KEV (exploitation date not opened; match Inferred) | [47][39][40][8] |
| [`T1219`](/mitre/techniques/T1219.md) | Remote Access Tools | command-and-control | Listed (C0002) | Night Dragon | [47] |
| [`T1550.002`](/mitre/techniques/T1550-002.md) | Pass the Hash | lateral-movement | Listed (C0002) | Night Dragon | [47] |
| [`T1568`](/mitre/techniques/T1568.md) | Dynamic Resolution | command-and-control | Listed (C0002) | Night Dragon | [47] |
| [`T1583.004`](/mitre/techniques/T1583-004.md) | Server | resource-development | Listed (C0002) | Night Dragon | [47] |
| [`T1584.004`](/mitre/techniques/T1584-004.md) | Server | resource-development | Listed (C0002) | Night Dragon | [47] |
| [`T1588.001`](/mitre/techniques/T1588-001.md) | Malware | resource-development | Listed (C0002) | Night Dragon | [47] |
| [`T1588.002`](/mitre/techniques/T1588-002.md) | Tool | resource-development | Listed (C0002) | Night Dragon | [47] |
| [`T1608.001`](/mitre/techniques/T1608-001.md) | Upload Malware | resource-development | Listed (C0002) | Night Dragon | [47] |
| [`T1685`](/mitre/techniques/T1685.md) | Disable or Modify Tools | defense-impairment | Listed (C0002) | Night Dragon | [47] |
| [`T1091`](/mitre/techniques/T1091.md) | Replication Through Removable Media | lateral-movement, initial-access | Listed (S0603); Described | Stuxnet's shortcut flaw from USB drives (Jul); the 2008 CENTCOM flash drive (disclosed 1 Sep) | [34][22][23][25][38] |
| [`T1210`](/mitre/techniques/T1210.md) | Exploitation of Remote Services | lateral-movement | Listed (S0603); Described | Stuxnet through MS08-067 and the print spooler flaw (MS10-061, 14 Sep; ICSA-10-272-01) | [34][29][31] |
| [`T1021.002`](/mitre/techniques/T1021-002.md) | SMB/Windows Admin Shares | lateral-movement | Listed (S0603); Described | Stuxnet through network shares (ICSA-10-238-01B, ICSA-10-272-01) | [34][28][29] |
| [`T1080`](/mitre/techniques/T1080.md) | Taint Shared Content | lateral-movement | Listed (S0603); Described | Stuxnet through STEP 7 project files (ICSA-10-272-01; match Inferred) | [34][29] |
| [`T1505.001`](/mitre/techniques/T1505-001.md) | SQL Stored Procedures | persistence | Listed (S0603); Described | Stuxnet through WinCC database files and SQL databases (ICSA-10-238-01B, ICSA-10-272-01; match Inferred) | [34][28][29] |
| [`T1068`](/mitre/techniques/T1068.md) | Exploitation for Privilege Escalation | privilege-escalation | Listed (S0603); Described | Stuxnet's privilege-escalation zero-days CVE-2010-2743 and CVE-2010-3338 (MS10-073, MS10-092); CVE-2010-3904 in KEV (match Inferred) | [34][32][53][55][64] |
| [`T1014`](/mitre/techniques/T1014.md) | Rootkit | stealth | Listed (S0603); Described | Stuxnet's signed kernel-mode rootkit (ICSA-10-238-01B) | [34][28] |
| [`T1553.002`](/mitre/techniques/T1553-002.md) | Code Signing | defense-impairment | Listed (S0603); Described | Drivers signed with the Realtek and JMicron certificates, revoked 16 and 22 Jul | [34][28][30] |
| [`T1078.001`](/mitre/techniques/T1078-001.md) | Default Accounts | stealth, persistence, privilege-escalation, initial-access | Listed (S0603); Described | Hard-coded WinCC and PCS 7 password CVE-2010-2772 (Jul) | [34][33] |
| [`T1570`](/mitre/techniques/T1570.md) | Lateral Tool Transfer | lateral-movement | Listed (S0603) | Stuxnet's peer-to-peer RPC updates (ICSA-10-272-01; match Inferred) | [34][29] |
| [`T1102`](/mitre/techniques/T1102.md) | Web Service | command-and-control | Described | Shadows in the Cloud: command and control over Twitter, Google Groups, Blogspot, Baidu Blogs, blog.com and Yahoo Mail (6 Apr) | [18] |
| [`T1539`](/mitre/techniques/T1539.md) | Steal Web Session Cookie | credential-access | Described | Apache JIRA cross-site scripting link stole administrators' sessions (5 to 9 Apr); Firesheep (24 Oct; match Inferred) | [17][68] |
| [`T1110`](/mitre/techniques/T1110.md) | Brute Force | credential-access | Described | Apache JIRA login brute-forced, succeeding on 6 Apr | [17] |
| [`T1566`](/mitre/techniques/T1566.md) | Phishing | initial-access | Described | Zeus sent as an apparently benign e-mail (charged 30 Sep); the release does not say attachment or link | [42] |
| [`T1056.001`](/mitre/techniques/T1056-001.md) | Keylogging | collection, credential-access | Described | Zeus recorded keystrokes at online-banking login (charged 30 Sep) | [42] |
| [`T1657`](/mitre/techniques/T1657.md) | Financial Theft | impact | Described | Zeus transfers to mule accounts (30 Sep); Trident Breach's USD 70 million (1 Oct) | [42][43][44] |
| [`T1498`](/mitre/techniques/T1498.md) | Network Denial of Service | impact | Described | PayPal attacks (6 to 10 Dec, as charged); Mariposa used for denial-of-service attacks (Jul) | [46][16] |
| [`T1593.001`](/mitre/techniques/T1593-001.md) | Social Media | reconnaissance | Reported | Aurora attackers profiled employees on social networks (USCC citing Google's security manager) | [10] |
| [`T1566.003`](/mitre/techniques/T1566-003.md) | Spearphishing via Service | initial-access | Reported | Aurora attackers posed as an acquaintance in a chat session (USCC citing Google's security manager) | [10] |
| [`T1505.003`](/mitre/techniques/T1505-003.md) | Web Shell | persistence | Inferred | Apache attackers changed the attachment path so JSP files would run (Apr) | [17] |
| [`T1550.004`](/mitre/techniques/T1550-004.md) | Web Session Cookie | lateral-movement | Inferred | Firesheep account takeover with captured cookies (24 Oct); Apache's stolen administrator sessions (Apr) | [68][17] |
| [`T1040`](/mitre/techniques/T1040.md) | Network Sniffing | credential-access, discovery | Inferred | Firesheep captured cookies on open Wi-Fi (24 Oct) | [68] |
| [`T1574.001`](/mitre/techniques/T1574-001.md) | DLL | stealth, execution | Inferred | DLL preloading ("binary planting") class, Advisory 2269637 (23 Aug); no exploited event in the record | [37] |

Left out on purpose: any technique for the China Telecom route event, which the USCC says it cannot interpret [10]; any technique for the AT&T iPad exposure, whose complaint as summarized names no flaw [20]; any technique for Waledac beyond its spam, which ATT&CK does not model as a technique, and any Waledac, Mariposa or Zeus software object, none of which the library's data carries for 2010 (S0016 P2P ZeuS is the later Gameover variant) [15][16][42][84]; T1189 for CVE-2010-1885 and the other browser flaws, whose delivery the bulletins opened here do not describe [21]; T1557 Adversary-in-the-Middle for RFC 5746, which fixed a protocol gap with no exploitation in the record [70]; the 30 Stuxnet techniques no 2010 primary opened here describes, which the home study binds [34][87]; and Flame's and Operation Dust Storm's techniques, which were written years later [48][84].

### ATT&CK for ICS

Stuxnet is the year's industrial event, and the [Stuxnet](/case-studies/STUXNET.md) study carries its full ICS mapping, 25 techniques in the library's ICS data (Confirmed [87]; Demonstrated [84]). The table lists the ten ICS techniques ATT&CK lists for S0603 that the 2010 record most directly supports; names and tactics are those in `data/attack/ics/`. The library has no generated pages for ICS techniques, so the ids are plain text; the ten are saved in the study's ATT&CK for ICS layer, described under Navigator layers below (Demonstrated [84][86]).

| Id | Name (ATT&CK for ICS v20.0) | Tactic(s) | Object | Basis | Dated event or report | Sources |
|---|---|---|---|---|---|---|
| T0847 | Replication Through Removable Media | initial-access | S0603 Stuxnet | Listed; Described | USB malware targeting Siemens control software (Jul) | [34][22] |
| T0866 | Exploitation of Remote Services | initial-access, lateral-movement | S0603 Stuxnet | Listed; Described | MS08-067 and the print spooler flaw (Sep) | [34][29] |
| T0873.001 | Siemens Project File Format | persistence | S0603 Stuxnet | Listed; Described | Propagation through STEP 7 project files (ICSA-10-272-01) | [34][29] |
| T0843 | Program Download | lateral-movement | S0603 Stuxnet | Listed; Described | PLC code injection reported (6 Aug) | [34][30] |
| T0889 | Modify Program | persistence | S0603 Stuxnet | Listed | Stuxnet (ATT&CK object) | [34] |
| T0821 | Modify Controller Tasking | execution | S0603 Stuxnet | Listed | Stuxnet (ATT&CK object) | [34] |
| T0851 | Rootkit | evasion, inhibit-response-function | S0603 Stuxnet | Listed | Stuxnet (ATT&CK object) | [34] |
| T0836 | Modify Parameter | impair-process-control | S0603 Stuxnet | Listed | Stuxnet (ATT&CK object) | [34] |
| T0831 | Manipulation of Control | impact | S0603 Stuxnet | Listed | Stuxnet (ATT&CK object) | [34] |
| T0832 | Manipulation of View | impact | S0603 Stuxnet | Listed | Stuxnet (ATT&CK object) | [34] |

ATT&CK also lists T0882 Theft of Operational Information for S0143 Flame; it is context only, because Flame was disclosed in 2012 (Confirmed [48]; Demonstrated [84]).

### ATT&CK groups, software and campaigns

| Object | Id | Binding | Sources |
|---|---|---|---|
| Elderwood | [G0066](/mitre/groups/G0066.md) | Bound with a caveat: ATT&CK's "suspected" group "reportedly responsible" for Aurora; Google names no state; all 9 techniques in the layer | [11][1] |
| Hydraq | [S0203](/mitre/software/S0203.md) | Bound with a caveat: ATT&CK says first used by Elderwood in the 2009 Google intrusion; aliases include Aurora; all 19 techniques in the layer | [12] |
| Axiom | [G0001](/mitre/groups/G0001.md) | Context: ATT&CK associates Hydraq with Axiom as well as Elderwood | [12] |
| PoisonIvy, Briba, Naid, Wiarp, Vasport, Pasam, Nerex, Linfo | [S0012](/mitre/software/S0012.md), [S0204](/mitre/software/S0204.md), [S0205](/mitre/software/S0205.md), [S0206](/mitre/software/S0206.md), [S0207](/mitre/software/S0207.md), [S0208](/mitre/software/S0208.md), [S0210](/mitre/software/S0210.md), [S0211](/mitre/software/S0211.md) | Context: listed among Elderwood's software across 2009 to 2012 reporting; not tied to a 2010 event here | [11][84] |
| Night Dragon | [C0002](/mitre/campaigns/C0002.md) | Bound: active through all of 2010; all 29 techniques in the layer | [47] |
| ASPXSpy, at, gsecdump, PsExec, zwShell | [S0073](/mitre/software/S0073.md), [S0110](/mitre/software/S0110.md), [S0008](/mitre/software/S0008.md), [S0029](/mitre/software/S0029.md), [S0350](/mitre/software/S0350.md) | Bound through C0002, whose software ATT&CK lists | [47][84] |
| Stuxnet | [S0603](/mitre/software/S0603.md) | Bound: discovered 2010; 10 of its 44 Enterprise techniques and 10 of its 25 ICS techniques bound here, the rest in the home study | [34][84] |
| Flame | [S0143](/mitre/software/S0143.md) | Context only: "active since at least 2010", disclosed 2012 | [48] |
| Operation Dust Storm | [C0016](/mitre/campaigns/C0016.md) | Context only: first seen January 2010 in the library's data | [84] |

The library's ATT&CK data has no object for Waledac, Mariposa or the Butterfly Bot, the 2010 Zeus ring, the Shadows in the Cloud operators, the PayPal attackers or the Apache attackers (Demonstrated [84]).

### CWE and CAPEC

The CWE column names the source of each id. Names are those in the library's CWE and CAPEC data, and every CAPEC listed has a page under `/mitre/capec/` (Demonstrated [85][86]). The library has no per-CWE generated pages, so CWE ids are plain text; the [CWE reference](/CWE_REFERENCE.md) is the library's entry point. The CAPEC column uses the ids the library's CWE, CAPEC or technique data relates, unless marked as this study's pairing (Demonstrated [85]).

| CWE | Weakness (library name) | Basis | 2010 record | CAPEC |
|---|---|---|---|---|
| CWE-416 | Use After Free | NVD, KEV | Internet Explorer (CVE-2010-0249, Aurora) | None (the library relates none) |
| CWE-787 | Out-of-bounds Write | KEV; NVD; CISA ADP | Flash and Reader (CVE-2010-1297, KEV); Office RTF (CVE-2010-3333, NVD); Reader CoolType (CVE-2010-2883, ADP) | None (the library relates none) |
| CWE-119 | Improper Restriction of Operations within the Bounds of a Memory Buffer | KEV | Reader CoolType (CVE-2010-2883); Office RTF (CVE-2010-3333) | [CAPEC-100](/mitre/capec/CAPEC-100.md) Overflow Buffers |
| CWE-94 | Improper Control of Generation of Code | KEV | Reader and Acrobat (CVE-2010-0188) | None assigned (the library relates CAPEC-242, CAPEC-35 and CAPEC-77; none is specific to this flaw) |
| CWE-20 | Improper Input Validation | KEV; NVD | Shortcut flaw (CVE-2010-2568, KEV); Print Spooler (CVE-2010-2729, NVD); Task Scheduler (CVE-2010-3338, NVD) | None assigned |
| CWE-22 | Improper Limitation of a Pathname to a Restricted Directory | KEV | ColdFusion administrator (CVE-2010-2861) | [CAPEC-126](/mitre/capec/CAPEC-126.md) Path Traversal, which the library relates |
| CWE-798 | Use of Hard-coded Credentials | NVD | Siemens WinCC and PCS 7 (CVE-2010-2772, Stuxnet) | [CAPEC-70](/mitre/capec/CAPEC-70.md) Try Common or Default Usernames and Passwords; [CAPEC-191](/mitre/capec/CAPEC-191.md) Read Sensitive Constants Within an Executable |
| NVD-CWE-noinfo | (as NVD lists it) | NVD | Shortcut flaw (CVE-2010-2568) | None |
| CWE-319 | Cleartext Transmission of Sensitive Information | Study's pairing | Firesheep's cleartext session cookies (24 Oct) | [CAPEC-102](/mitre/capec/CAPEC-102.md) Session Sidejacking; [CAPEC-65](/mitre/capec/CAPEC-65.md) Sniff Application Code |
| CWE-79 | Improper Neutralization of Input During Web Page Generation | Top 25 entry; study's pairing for events | 2010 Top 25 rank 1; Apache JIRA link (Apr) and Twitter onMouseOver (21 Sep) | [CAPEC-63](/mitre/capec/CAPEC-63.md) Cross-Site Scripting (XSS) |
| CWE-427 | Uncontrolled Search Path Element | Study's pairing | DLL preloading, Advisory 2269637 (23 Aug) | [CAPEC-471](/mitre/capec/CAPEC-471.md) Search Order Hijacking, which the library relates |
| CWE-89, CWE-120, CWE-352, CWE-285 | Improper Neutralization of Special Elements used in an SQL Command; Buffer Copy without Checking Size of Input; Cross-Site Request Forgery; Improper Authorization | Top 25 entries, no 2010 event bound | 2010 Top 25 ranks 2 to 5 | [CAPEC-66](/mitre/capec/CAPEC-66.md) SQL Injection; [CAPEC-100](/mitre/capec/CAPEC-100.md) Overflow Buffers; [CAPEC-62](/mitre/capec/CAPEC-62.md) Cross Site Request Forgery |
| none bound | (removable media) | Library data | Stuxnet's USB spread; the CENTCOM flash drive | [CAPEC-457](/mitre/capec/CAPEC-457.md) USB Memory Attacks (the library lists it on T1091) |
| none bound | (code signing) | Library data | Stuxnet's signed drivers | [CAPEC-68](/mitre/capec/CAPEC-68.md) Subvert Code-signing Facilities (on T1553.002) |
| none bound | (rootkit) | Library data | Stuxnet's kernel rootkit | [CAPEC-552](/mitre/capec/CAPEC-552.md) Install Rootkit (on T1014) |
| none bound | (shared content) | Library data | STEP 7 project files | [CAPEC-562](/mitre/capec/CAPEC-562.md) Modify Shared File (on T1080) |
| none bound | (admin shares) | Library data | Stuxnet through network shares | [CAPEC-561](/mitre/capec/CAPEC-561.md) Windows Admin Shares with Stolen Credentials (on T1021.002) |
| none bound | (session theft) | Library data | Apache JIRA; Firesheep | [CAPEC-21](/mitre/capec/CAPEC-21.md) Exploitation of Trusted Identifiers; [CAPEC-31](/mitre/capec/CAPEC-31.md) Accessing/Intercepting/Modifying HTTP Cookies (on T1539) |
| none bound | (brute force) | Library data | Apache JIRA login | [CAPEC-112](/mitre/capec/CAPEC-112.md) Brute Force (on T1110) |
| none bound | (web shell) | Library data | Apache JSP step | [CAPEC-650](/mitre/capec/CAPEC-650.md) Upload a Web Shell to a Web Server (on T1505.003) |
| none bound | (keylogging) | Library data | Zeus at banking login | [CAPEC-568](/mitre/capec/CAPEC-568.md) Capture Credentials via Keylogger (on T1056.001) |
| none bound | (phishing) | Library data | Zeus by e-mail; Aurora chat lure; Elderwood; Night Dragon | [CAPEC-98](/mitre/capec/CAPEC-98.md) Phishing (on T1566); [CAPEC-163](/mitre/capec/CAPEC-163.md) Spear Phishing (on T1566.001, T1566.002 and T1566.003) |
| none bound | (Night Dragon credentials) | Library data | Night Dragon | [CAPEC-55](/mitre/capec/CAPEC-55.md) Rainbow Table Password Cracking (on T1110.002); [CAPEC-644](/mitre/capec/CAPEC-644.md) Use of Captured Hashes (Pass The Hash) (on T1550.002); [CAPEC-555](/mitre/capec/CAPEC-555.md) Remote Services with Stolen Credentials (on T1133); [CAPEC-560](/mitre/capec/CAPEC-560.md) Use of Known Domain Credentials (on T1078) |
| none bound | (library loading) | Library data | DLL preloading advisory | [CAPEC-471](/mitre/capec/CAPEC-471.md) Search Order Hijacking; [CAPEC-641](/mitre/capec/CAPEC-641.md) DLL Side-Loading (on T1574.001) |
| none bound | (protocol, no event) | Library data | RFC 5746 context | [CAPEC-94](/mitre/capec/CAPEC-94.md) Adversary in the Middle (AiTM) (on T1557; no 2010 event bound) |

### D3FEND countermeasures

The technique-to-countermeasure links come from the library's D3FEND data; pairing them with the 2010 record is this study's reading (Demonstrated [85]; Inferred). Every page exists under `/mitre/d3fend/` (Demonstrated [86]).

| Technique or event from the record | D3FEND countermeasures (D3FEND tactic) | 2010 analogue |
|---|---|---|
| T1203, T1068 | [Process Segment Execution Prevention](/mitre/d3fend/process-segment-execution-prevention.md) (Harden); [Segment Address Offset Randomization](/mitre/d3fend/segment-address-offset-randomization.md) (Harden); [Stack Frame Canary Validation](/mitre/d3fend/stack-frame-canary-validation.md) (Harden); [Shadow Stack Comparisons](/mitre/d3fend/shadow-stack-comparisons.md) (Detect); [Memory Boundary Tracking](/mitre/d3fend/memory-boundary-tracking.md) (Detect); [Process Code Segment Verification](/mitre/d3fend/process-code-segment-verification.md) (Detect) | The exploited browser, document and kernel flaws [4][45][53][55]; no 2010 source opened here names these controls (Inferred) |
| T1091 | [IO Port Restriction](/mitre/d3fend/io-port-restriction.md) (Isolate); [Hardware Component Inventory](/mitre/d3fend/hardware-component-inventory.md) (Model) | Stuxnet's USB spread and ICS-CERT's USB advice [22]; the CENTCOM flash drive [38] |
| T1189 | [URL Analysis](/mitre/d3fend/url-analysis.md) (Detect); [URL Reputation Analysis](/mitre/d3fend/url-reputation-analysis.md) (Detect); [Network Traffic Filtering](/mitre/d3fend/network-traffic-filtering.md) (Isolate) | The Aurora link to a malicious site (Reported [10]) |
| T1210 | [Network Traffic Filtering](/mitre/d3fend/network-traffic-filtering.md) (Isolate); [Connection Attempt Analysis](/mitre/d3fend/connection-attempt-analysis.md) (Detect) | Stuxnet through MS08-067 and the print spooler [29][31]; MS10-046's advice to block outbound SMB [25] |
| T1078.001 | [Change Default Password](/mitre/d3fend/change-default-password.md) (Harden); [Account Locking](/mitre/d3fend/account-locking.md) (Evict) | The hard-coded WinCC password [33] |
| T1014 | [File Integrity Monitoring](/mitre/d3fend/file-integrity-monitoring.md) (Detect); [Software Update](/mitre/d3fend/software-update.md) (Harden) | Stuxnet's rootkit [28] |
| T1553.002 (no link in the library) | [Certificate Analysis](/mitre/d3fend/certificate-analysis.md) (study's pairing) | Revoked Realtek and JMicron certificates [30] (Inferred) |
| T1080 | [Network Resource Access Mediation](/mitre/d3fend/network-resource-access-mediation.md) (Isolate); [Decoy Network Resource](/mitre/d3fend/decoy-network-resource.md) (Deceive) | STEP 7 project files on shares [29] |
| T1566.001 | [Email Filtering](/mitre/d3fend/email-filtering.md) (Isolate); [File Analysis](/mitre/d3fend/file-analysis.md) (Detect); [Dynamic Analysis](/mitre/d3fend/dynamic-analysis.md) (Detect) | Elderwood's attachments [11]; Zeus by e-mail [42] (Inferred) |
| T1056.001 | [Input Device Analysis](/mitre/d3fend/input-device-analysis.md) (Detect) | Zeus keylogging at banking login [42] |
| T1539, T1550.004 | [Credential Revocation](/mitre/d3fend/credential-revocation.md) (Evict); [Multi-factor Authentication](/mitre/d3fend/multi-factor-authentication.md) (Harden); [Authentication Cache Invalidation](/mitre/d3fend/authentication-cache-invalidation.md) (Evict) | Apache's stolen sessions [17]; Firesheep [68] |
| T1190 | [Inbound Traffic Filtering](/mitre/d3fend/inbound-traffic-filtering.md) (Isolate); [Client-server Payload Profiling](/mitre/d3fend/client-server-payload-profiling.md) (Detect) | ASP.NET padding oracle [39]; JBoss, ColdFusion and Exim in KEV [8]; Night Dragon [47] |
| T1505.003 | [Executable Allowlisting](/mitre/d3fend/executable-allowlisting.md) (Isolate); [File Integrity Monitoring](/mitre/d3fend/file-integrity-monitoring.md) (Detect); [Process Spawn Analysis](/mitre/d3fend/process-spawn-analysis.md) (Detect) | Apache's JSP step [17] |
| T1102 | [Outbound Traffic Filtering](/mitre/d3fend/outbound-traffic-filtering.md) (Isolate); [Relay Pattern Analysis](/mitre/d3fend/relay-pattern-analysis.md) (Detect) | Shadows in the Cloud's command and control over web services [18] |
| T1574.001 | [File Integrity Monitoring](/mitre/d3fend/file-integrity-monitoring.md) (Detect); [Local File Permissions](/mitre/d3fend/local-file-permissions.md) (Isolate) | DLL preloading advisory [37] |
| T1040 | [DNS Traffic Analysis](/mitre/d3fend/dns-traffic-analysis.md) (Detect), the only countermeasure the library links | Firesheep [68]; the closer 2010 control was [Message Encryption](/mitre/d3fend/message-encryption.md) (study's pairing, Inferred) |

The library links T1110, T1566, T1498, T1553.002 and T1021.002 to no D3FEND countermeasure (Demonstrated [85]). ATT&CK mitigation pages exist for [M1051 Update Software](/mitre/mitigations/M1051.md), [M1042 Disable or Remove Feature or Program](/mitre/mitigations/M1042.md), [M1034 Limit Hardware Installation](/mitre/mitigations/M1034.md), [M1037 Filter Network Traffic](/mitre/mitigations/M1037.md), [M1049 Antivirus/Antimalware](/mitre/mitigations/M1049.md), [M1017 User Training](/mitre/mitigations/M1017.md), [M1050 Exploit Protection](/mitre/mitigations/M1050.md), [M1021 Restrict Web-Based Content](/mitre/mitigations/M1021.md), [M1041 Encrypt Sensitive Information](/mitre/mitigations/M1041.md), [M1032 Multi-factor Authentication](/mitre/mitigations/M1032.md), [M1027 Password Policies](/mitre/mitigations/M1027.md), [M1036 Account Use Policies](/mitre/mitigations/M1036.md), [M1048 Application Isolation and Sandboxing](/mitre/mitigations/M1048.md), [M1038 Execution Prevention](/mitre/mitigations/M1038.md), [M1045 Code Signing](/mitre/mitigations/M1045.md) and [M1026 Privileged Account Management](/mitre/mitigations/M1026.md) (Demonstrated [86]). ICS-CERT's Stuxnet advice maps most closely to M1042 (disable AutoRun and shortcut icons), M1034 (USB caution), M1026 (least privilege), M1049 (current antivirus) and M1051 (the Siemens and Microsoft updates); MS10-046's gateway and SMB workarounds to M1037; and Gmail's default HTTPS to M1041 (Inferred [22][25][76]).

### Navigator layers

The study's Enterprise techniques are saved as an ATT&CK Navigator layer pinned to ATT&CK v20, [navigator/library-layers/chronicle-2010.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/chronicle-2010.json), in the format of the existing chronicle layers: domain enterprise-attack, described as a curated case-study layer and not an official MITRE mapping (Demonstrated [88]). It lists the 71 techniques in the Enterprise table under each tactic they carry in v20.0, 88 technique-tactic entries in all, and is listed on [the Navigator layers page](/navigator/index.md). The ten ICS techniques in the ATT&CK for ICS table are saved in a second layer, [navigator/case-studies/chronicle-2010-ics.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/case-studies/chronicle-2010-ics.json), domain ics-attack, 12 technique-tactic entries, each scored 100 because ATT&CK lists the id for S0603; the home study's [Stuxnet layer](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/stuxnet-s0603.json) and its ICS layer carry all of Stuxnet. Scores show the basis, not severity, in the house scale set by the 2016 chronicle: 100 where an ATT&CK object prints the id, 70 where a primary source describes the behavior and this study assigns the id, 50 where only a Reported source supports it, and 40 for an Inferred mapping (Demonstrated [88]). The 58 techniques listed for G0066, S0203, C0002 or S0603 score 100, with a comment noting that Elderwood's tie to Aurora is "reportedly" and that Hydraq's techniques come from later analyses; T1102, T1539, T1110, T1566, T1056.001, T1657 and T1498 score 70; T1593.001 and T1566.003 score 50; T1505.003, T1550.004, T1040 and T1574.001 score 40. Each entry's comment names the source numbers in the Sources table below.

## Cross-cutting themes

**The headline events were disclosures.** Aurora was detected in 2009 and disclosed in 2010; Buckshot Yankee happened in 2008 and was disclosed in 2010; Stuxnet's components date from 2008 and it was discovered in 2010 (Confirmed [1][38][34]).

**Removable media crossed every boundary.** A flash drive reached classified military networks in 2008 and a USB worm reached Siemens control software in 2010, both disclosed this year (Confirmed [38][22]).

**Documents and browsers carried the attacks.** Internet Explorer, Firefox, Reader, Flash and Office flaws were exploited at or before their fixes from January to December (Confirmed [4][52][56][60][62][63][45]).

**Encryption and integrity defaults moved.** Gmail, HTTPS Everywhere, RFC 5746 and the signed DNS root all date from 2010, and Firesheep made the case in public (Confirmed [76][77][70][73][68]).

**Courts did the takedowns.** A civil restraining order cut off Waledac, police in Spain and Slovenia arrested Mariposa's suspected operators and creator, and Zeus cases ran in the US, UK, Ukraine and the Netherlands (Confirmed [15][16][43]).

**The record named places, not perpetrators.** Google said "originating from China", Shadows in the Cloud placed the attackers in Chengdu by circumstantial evidence, and the USCC assessed rather than found state involvement and could not tell what was done with the diverted traffic (Confirmed [1][18][10]).

**Governments organized and exercised.** Cyber Command began operations, Cyber Storm III ran, NIST moved to a life-cycle risk framework and smart grid guidance, and the UK funded a national programme (Confirmed [38][79][69][78][80]).

### What is overstated and what is understated

This section is the study's reading of the record (Inferred).

- **Overstated: Aurora as one campaign with one exploit.** Google's post names no exploit, and ATT&CK ties Hydraq to Elderwood only through later reporting, with techniques from 2009 to 2012 [1][11][12].
- **Overstated: the number of companies hit by Aurora.** Google's post says "at least twenty other large companies"; the library's Notable Incidents line says "30+", a figure no source opened here gives, and names groups ATT&CK does not tie to Aurora [1][87].
- **Overstated: "Chinese state hacking" for Aurora, the Shadow network and the route event.** Google says "originating from China", the Shadows report places the attackers in Chengdu only circumstantially, and the USCC's state involvement is an assessment, not a finding [1][18][10].
- **Overstated: the route event as a hijack.** The USCC says the bad data appear to have originated at IDC China Telecommunication and that it cannot determine what, if anything, was done with the traffic; the 15 percent counts destinations, not traffic volume [10].
- **Overstated: Stuxnet as the "first cyberweapon" with novel lessons.** The 2010 defender advice was ordinary: removable-media policy, patching, least privilege and default credentials [22][28][33].
- **Overstated: the botnet and theft figures.** Mariposa's 8 to 12 million is an industry estimate, Waledac's 1.5 billion spam a day is Microsoft's estimate, and the USD 70 million is the FBI's aggregate across a ring, not a single theft [16][15][43].
- **Overstated: the precision of ids on 2010 events.** No ATT&CK mapping existed in 2010, every technique id here is assigned in hindsight, and KEV came 11 to 16 years later [5][8].
- **Understated: the KEV tail.** CVE-2010-0249 and CVE-2010-0806 entered KEV in 2026 and CVE-2010-3962 and CVE-2010-3765 in 2025 [8].
- **Understated: how the year's defaults spread.** The signed root, default HTTPS and RFC 5746 date from 2010; how fast they were adopted is outside the record opened here [73][76][70].
- **Understated: the AT&T exposure.** An unauthenticated web enumeration became a federal prosecution [20].
- **Understated: Buckshot Yankee.** The 2008 compromise was the most significant breach of US military computers, in the Deputy Secretary's words, and it appears in the 2010 record only as a disclosure [38].
- **Understated: the regulator record.** This study could not open the primaries for 2010 regulator and state data-security actions (listed under Scope and method), so it does not cover them.

### Discrepancies in the record

- **When Stuxnet became public.** Symantec dates VirusBlokAda's report to 17 June; CERT/CC gives 10 July as the date public and 15 July as its first publication; Microsoft's advisory is dated 16 July [30][26][24].
- **ICSA-10-201's date.** The page shows only its 2014 revision, not an original release date [22].
- **Siemens' infection count.** Four infected customers in ICSA-10-201-01C; 15 infections worldwide on 7 September in ICSA-10-238-01B; about 100,000 infected hosts in Symantec's count, which is all hosts, not Siemens customers [22][28][30].
- **Stuxnet's vulnerabilities.** ICSA-10-238-01B says five, MS08-067 and four zero-days; ICSA-10-272-01 says four zero-days, two patched by then, plus MS08-067 [28][29].
- **CVE-2010-2568's weakness.** KEV lists CWE-20; NVD lists NVD-CWE-noinfo [8][27].
- **CVE-2010-3333's and CVE-2010-2883's weaknesses.** KEV lists CWE-119 for both; NVD lists CWE-787 for CVE-2010-3333 and the CISA ADP entry lists CWE-787 for CVE-2010-2883 [8][65][62].
- **CVE-2010-0188's publication date.** The CVE record gives 21 February; NVD gives 22 February [58][65].
- **Elderwood's techniques.** The live ATT&CK page shows T1027 as the parent row of T1027.002 and T1027.013; the library's data maps only the two sub-techniques to G0066 [11][84].
- **Butler's fraud figure.** The 12 February release counts more than 1.8 million card numbers; the 8 December release says more than 1.8 million cards with more than USD 87 million in fraud and more than 10,000 banks [13][14].
- **The Zeus totals.** SDNY's charges cover more than USD 3 million; the FBI's ring-wide figures are USD 70 million stolen and about USD 220 million attempted [42][43].
- **Shadows in the Cloud's date.** The report is dated 6 April; Citizen Lab's op-ed of 7 April calls it released "today" [18][19].
- **The KEV tail's range.** The first two CVE-2010 entries, SAP NetWeaver CVE-2010-5326 and JBoss Seam CVE-2010-1871, were added in November and December 2021, the month KEV began [8].
- **Aurora's attribution in the library.** Notable Incidents names "APT10 / Comment Crew (Chinese PLA Unit 61398, attributed)"; ATT&CK maps Aurora to Elderwood [87][11].

## Sources

Every external source was opened on 12 November 2026, and the library data checks were run on 12 and 13 November 2026, as the Opened column shows. All are checked as of 13 November 2026. Grade is the source's evidence grade as used in this study. The address of source 82 is shown as code rather than as a link because sec.gov refuses automated link checkers; copy it into a browser to open it.

| # | Source | URL | Opened | Grade |
|---|---|---|---|---|
| 1 | Google Official Blog, A new approach to China, 12 Jan 2010 | https://googleblog.blogspot.com/2010/01/new-approach-to-china.html | 2026-11-12 | Confirmed |
| 2 | Google Official Blog, A new approach to China: an update, 22 Mar 2010 | https://googleblog.blogspot.com/2010/03/new-approach-to-china-update.html | 2026-11-12 | Confirmed |
| 3 | Microsoft Security Advisory 979352, 14 Jan 2010 | https://learn.microsoft.com/en-us/security-updates/securityadvisories/2010/979352 | 2026-11-12 | Confirmed |
| 4 | Microsoft Security Bulletin MS10-002, 21 Jan 2010 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-002 | 2026-11-12 | Confirmed |
| 5 | NVD, CVE-2010-0249 (API record and detail page) | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2010-0249 ; https://nvd.nist.gov/vuln/detail/CVE-2010-0249 | 2026-11-12 | Confirmed |
| 6 | CVE Program, CVE-2010-0249 record | https://cveawg.mitre.org/api/cve/CVE-2010-0249 | 2026-11-12 | Confirmed |
| 7 | CERT/CC, VU#492515, 14 Jan 2010 | https://www.kb.cert.org/vuls/id/492515 | 2026-11-12 | Confirmed |
| 8 | CISA, Known Exploited Vulnerabilities catalog (JSON feed, version 2026.11.10) | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | 2026-11-12 | Confirmed; Demonstrated (counts) |
| 9 | US Department of State (archived), Secretary Clinton, Remarks on Internet Freedom, 21 Jan 2010 | https://2009-2017.state.gov/secretary/20092013clinton/rm/2010/01/135519.htm | 2026-11-12 | Confirmed |
| 10 | US-China Economic and Security Review Commission, 2010 Annual Report to Congress, Nov 2010 | https://www.uscc.gov/sites/default/files/annual_reports/2010-Report-to-Congress.pdf | 2026-11-12 | Confirmed (the Commission's account and assessment); Reported (the vendor and Google statements it quotes) |
| 11 | MITRE ATT&CK, G0066 Elderwood | https://attack.mitre.org/groups/G0066/ | 2026-11-12 | Confirmed (the object and its techniques); Reported (the Aurora attribution) |
| 12 | MITRE ATT&CK, S0203 Hydraq | https://attack.mitre.org/software/S0203/ | 2026-11-12 | Confirmed |
| 13 | FBI Pittsburgh (USAO W.D. Pa.), Butler sentencing release, 12 Feb 2010 | https://archives.fbi.gov/archives/pittsburgh/press-releases/2010/pt021210b.htm | 2026-11-12 | Confirmed |
| 14 | USAO W.D. Pa., release of 8 Dec 2010 | https://www.justice.gov/archive/usao/paw/news/2010/2010_december/2010_12_08_01.html | 2026-11-12 | Confirmed |
| 15 | Microsoft, Cracking Down on Botnets, 24 Feb 2010 (On the Issues and Microsoft blog copies) | https://blogs.microsoft.com/on-the-issues/2010/02/24/cracking-down-on-botnets/ ; https://blogs.microsoft.com/blog/2010/02/24/cracking-down-on-botnets/ | 2026-11-12 | Confirmed (the plaintiff's account of the order); Reported (Microsoft's estimates) |
| 16 | FBI, FBI, Slovenian and Spanish Police Arrest Mariposa Botnet Creator, Operators, 28 Jul 2010 | https://archives.fbi.gov/archives/news/pressrel/press-releases/fbi-slovenian-and-spanish-police-arrest-mariposa-botnet-creator-operators | 2026-11-12 | Confirmed (arrests); Reported (the infection estimate) |
| 17 | Apache Infrastructure Team, apache.org incident report for 04/09/2010, 13 Apr 2010 | https://infra.apache.org/blog/apache_org_04_09_2010 | 2026-11-12 | Confirmed |
| 18 | Information Warfare Monitor and Shadowserver Foundation, Shadows in the Cloud: Investigating Cyber Espionage 2.0, JR03-2010, 6 Apr 2010 (mirror at nartv.org; Citizen Lab copy) | https://www.nartv.org/mirror/shadows-in-the-cloud.pdf ; https://citizenlab.ca/wp-content/uploads/2017/05/shadows-in-the-cloud.pdf | 2026-11-12 | Confirmed (findings); Reported (the Chengdu location, which the report calls circumstantial) |
| 19 | Citizen Lab, Breaking up dark clouds in cyberspace, 7 Apr 2010 | https://citizenlab.ca/breaking-up-dark-clouds-in-cyberspace/ | 2026-11-12 | Confirmed |
| 20 | FBI Newark (USAO D.N.J.), AT&T iPad charges, 18 Jan 2011 | https://archives.fbi.gov/archives/newark/press-releases/2011/nk011811.htm | 2026-11-12 | Confirmed (as charged) |
| 21 | Microsoft Security Bulletin MS10-042, 13 Jul 2010 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-042 | 2026-11-12 | Confirmed |
| 22 | ICS-CERT, ICSA-10-201-01C, USB Malware Targeting Siemens Control Software (Update C) | https://www.cisa.gov/news-events/ics-advisories/icsa-10-201-01c | 2026-11-12 | Confirmed |
| 23 | US-CERT alert, Microsoft Windows .LNK Vulnerability, 16 Jul 2010 (CISA archive) | https://www.cisa.gov/news-events/alerts/2010/07/16/microsoft-windows-lnk-vulnerability | 2026-11-12 | Confirmed |
| 24 | Microsoft Security Advisory 2286198, 16 Jul 2010 | https://learn.microsoft.com/en-us/security-updates/securityadvisories/2010/2286198 | 2026-11-12 | Confirmed |
| 25 | Microsoft Security Bulletin MS10-046, 2 Aug 2010 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-046 | 2026-11-12 | Confirmed |
| 26 | CERT/CC, VU#940193, 15 Jul 2010 | https://www.kb.cert.org/vuls/id/940193 | 2026-11-12 | Confirmed |
| 27 | CVE Program and NVD, CVE-2010-2568 records | https://cveawg.mitre.org/api/cve/CVE-2010-2568 ; https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2010-2568 | 2026-11-12 | Confirmed |
| 28 | ICS-CERT, ICSA-10-238-01B, Stuxnet Malware Mitigation (Update B) | https://www.cisa.gov/news-events/ics-advisories/icsa-10-238-01b | 2026-11-12 | Confirmed |
| 29 | ICS-CERT, ICSA-10-272-01, Primary Stuxnet Advisory, Sep 2010 | https://www.cisa.gov/news-events/ics-advisories/icsa-10-272-01 | 2026-11-12 | Confirmed |
| 30 | Symantec, W32.Stuxnet Dossier, first published 30 Sep 2010 (version 1.4, Feb 2011) | https://docs.broadcom.com/doc/security-response-w32-stuxnet-dossier-11-en | 2026-11-12 | Confirmed (vendor's analysis) |
| 31 | Microsoft Security Bulletin MS10-061, 14 Sep 2010 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-061 | 2026-11-12 | Confirmed |
| 32 | CVE Program, CVE-2010-2743 record (with the CVE-2010-2729 record as read) | https://cveawg.mitre.org/api/cve/CVE-2010-2743 | 2026-11-12 | Confirmed |
| 33 | NVD, CVE-2010-2772 (API record) | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2010-2772 | 2026-11-12 | Confirmed |
| 34 | MITRE ATT&CK, S0603 Stuxnet | https://attack.mitre.org/software/S0603/ | 2026-11-12 | Confirmed |
| 35 | World Nuclear News, Bushehr unaffected by computer virus, 27 Sep 2010 (relaying Reuters) | https://world-nuclear-news.org/Articles/Bushehr-unaffected-by-computer-virus | 2026-11-12 | Reported |
| 36 | Christian Science Monitor, Stuxnet: Ahmadinejad admits cyberweapon hit Iran nuclear program, 30 Nov 2010 | https://www.csmonitor.com/USA/2010/1130/Stuxnet-Ahmadinejad-admits-cyberweapon-hit-Iran-nuclear-program | 2026-11-12 | Reported |
| 37 | Microsoft Security Advisory 2269637, 23 Aug 2010 | https://learn.microsoft.com/en-us/security-updates/securityadvisories/2010/2269637 | 2026-11-12 | Confirmed |
| 38 | William J. Lynn III, Defending a New Domain, Foreign Affairs, published 1 Sep 2010 | https://www.foreignaffairs.com/articles/united-states/2010-09-01/defending-new-domain | 2026-11-12 | Confirmed (an official's own statement) |
| 39 | Microsoft Security Advisory 2416728, 17 Sep 2010 | https://learn.microsoft.com/en-us/security-updates/securityadvisories/2010/2416728 | 2026-11-12 | Confirmed |
| 40 | Microsoft Security Bulletin MS10-070, 28 Sep 2010 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-070 | 2026-11-12 | Confirmed |
| 41 | Twitter (X) blog, All about the "onMouseOver" incident, 21 Sep 2010 | https://blog.x.com/en/company/all-about-the-onmouseover-incident | 2026-11-12 | Confirmed |
| 42 | FBI New York (USAO S.D.N.Y.), 37 defendants charged, 30 Sep 2010 | https://archives.fbi.gov/archives/newyork/press-releases/2010/nyfo093010.htm | 2026-11-12 | Confirmed (as charged) |
| 43 | FBI story, Cyber Banking Fraud, 1 Oct 2010 | https://archives.fbi.gov/archives/news/stories/2010/october/cyber-banking-fraud | 2026-11-12 | Confirmed |
| 44 | FBI, International Cooperation Disrupts Multi-Country Cyber Theft Ring, 1 Oct 2010 | https://archives.fbi.gov/archives/news/pressrel/press-releases/international-cooperation-disrupts-multi-country-cyber-theft-ring | 2026-11-12 | Confirmed |
| 45 | Microsoft Security Advisory 2458511, 3 Nov 2010 (resolved by MS10-090, 14 Dec 2010) | https://learn.microsoft.com/en-us/security-updates/securityadvisories/2010/2458511 | 2026-11-12 | Confirmed |
| 46 | FBI and DOJ, Sixteen Individuals Arrested in the United States for Alleged Roles in Cyber Attacks, 19 Jul 2011 | https://archives.fbi.gov/archives/news/pressrel/press-releases/sixteen-individuals-arrested-in-the-united-states-for-alleged-roles-in-cyber-attacks | 2026-11-12 | Confirmed (as charged) |
| 47 | MITRE ATT&CK, C0002 Night Dragon | https://attack.mitre.org/campaigns/C0002/ | 2026-11-12 | Confirmed (the record); Reported (the attribution) |
| 48 | MITRE ATT&CK, S0143 Flame | https://attack.mitre.org/software/S0143/ | 2026-11-12 | Confirmed |
| 49 | Microsoft Security Bulletin MS10-106, 14 Dec 2010 (the 2010 series, MS10-001 to MS10-106) | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-106 | 2026-11-12 | Confirmed (dates); Inferred (count) |
| 50 | Microsoft Security Bulletin MS10-071, 12 Oct 2010 (the October bulletins, MS10-071 to MS10-086) | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-071 | 2026-11-12 | Confirmed (dates); Inferred (counts) |
| 51 | Microsoft Security Bulletin MS10-015, 9 Feb 2010 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-015 | 2026-11-12 | Confirmed |
| 52 | Microsoft Security Bulletin MS10-018, 30 Mar 2010 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-018 | 2026-11-12 | Confirmed |
| 53 | Microsoft Security Bulletin MS10-073, 12 Oct 2010 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-073 | 2026-11-12 | Confirmed |
| 54 | Microsoft Security Bulletin MS10-087, 9 Nov 2010 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-087 | 2026-11-12 | Confirmed |
| 55 | Microsoft Security Bulletin MS10-092, 14 Dec 2010 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-092 | 2026-11-12 | Confirmed |
| 56 | Mozilla Foundation Security Advisory 2010-73, 27 Oct 2010 | https://www.mozilla.org/en-US/security/advisories/mfsa2010-73/ | 2026-11-12 | Confirmed |
| 57 | CVE Program, CVE-2010-3765 record | https://cveawg.mitre.org/api/cve/CVE-2010-3765 | 2026-11-12 | Confirmed |
| 58 | CVE Program, CVE-2010-0188 record | https://cveawg.mitre.org/api/cve/CVE-2010-0188 | 2026-11-12 | Confirmed |
| 59 | CVE Program, CVE-2010-0738 record | https://cveawg.mitre.org/api/cve/CVE-2010-0738 | 2026-11-12 | Confirmed |
| 60 | CVE Program, CVE-2010-1297 record | https://cveawg.mitre.org/api/cve/CVE-2010-1297 | 2026-11-12 | Confirmed |
| 61 | CVE Program, CVE-2010-2861 record | https://cveawg.mitre.org/api/cve/CVE-2010-2861 | 2026-11-12 | Confirmed |
| 62 | CVE Program, CVE-2010-2883 record | https://cveawg.mitre.org/api/cve/CVE-2010-2883 | 2026-11-12 | Confirmed |
| 63 | CVE Program, CVE-2010-3654 record | https://cveawg.mitre.org/api/cve/CVE-2010-3654 | 2026-11-12 | Confirmed |
| 64 | CVE Program, CVE-2010-4344 record (with the CVE-2010-4398 and CVE-2010-3904 records as read) | https://cveawg.mitre.org/api/cve/CVE-2010-4344 | 2026-11-12 | Confirmed |
| 65 | NVD, CVE-2010-3333 (API record; with CVE-2010-0188 as read) | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2010-3333 | 2026-11-12 | Confirmed |
| 66 | USAO D. Mass., Toey sentencing release, 16 Apr 2010 (records the Gonzalez sentence) | https://www.justice.gov/archive/usao/ma/news/2010/April/TOEYsentPR.html | 2026-11-12 | Confirmed |
| 67 | USAO D. Mass., Scott sentencing release, 29 Mar 2010 | https://www.justice.gov/archive/usao/ma/news/2010/March/ScottSentencingPR.html | 2026-11-12 | Confirmed |
| 68 | Eric Butler, Firesheep, 24 Oct 2010 | https://codebutler.com/2010/10/24/firesheep/ | 2026-11-12 | Confirmed (the author's post); Demonstrated (the tool) |
| 69 | NIST, SP 800-37 Revision 1 (original and update 1) | https://csrc.nist.gov/pubs/sp/800/37/r1/final ; https://csrc.nist.gov/pubs/sp/800/37/r1/upd1/final | 2026-11-12 | Confirmed |
| 70 | IETF, RFC 5746, Transport Layer Security (TLS) Renegotiation Indication Extension, Feb 2010 | https://www.rfc-editor.org/rfc/rfc5746 | 2026-11-12 | Confirmed |
| 71 | MITRE and SANS, 2010 CWE/SANS Top 25 Most Dangerous Software Errors | https://cwe.mitre.org/top25/archive/2010/2010_cwe_sans_top25.html | 2026-11-12 | Confirmed |
| 72 | OWASP, OWASP Top 10 2010 (PDF) | https://owasp.org/www-pdf-archive/OWASP_Top_10_-_2010.pdf | 2026-11-12 | Confirmed |
| 73 | IANA, root zone trust anchors (root-anchors.xml) | https://data.iana.org/root-anchors/root-anchors.xml | 2026-11-12 | Confirmed |
| 74 | Chromium Blog, Encouraging more Chromium security research, 28 Jan 2010 | https://blog.chromium.org/2010/01/encouraging-more-chromium-security.html | 2026-11-12 | Confirmed |
| 75 | Mozilla Security Blog, Refresh, 15 Jul 2010 | https://blog.mozilla.org/security/2010/07/15/refresh/ | 2026-11-12 | Confirmed |
| 76 | Official Gmail Blog, Default https access for Gmail, 12 Jan 2010 | https://gmail.googleblog.com/2010/01/default-https-access-for-gmail.html | 2026-11-12 | Confirmed |
| 77 | EFF, Encrypt the Web with the HTTPS Everywhere Firefox Extension, 17 Jun 2010 | https://www.eff.org/deeplinks/2010/06/encrypt-web-https-everywhere-firefox-extension | 2026-11-12 | Confirmed |
| 78 | NIST, NISTIR 7628, Guidelines for Smart Grid Cyber Security, 31 Aug 2010 | https://csrc.nist.gov/pubs/ir/7628/final | 2026-11-12 | Confirmed |
| 79 | DHS, Cyber Storm III Final Report | https://www.cisa.gov/sites/default/files/publications/CyberStorm%2520III%2520FINAL%2520Report.pdf | 2026-11-12 | Confirmed |
| 80 | UK Government, The Strategic Defence and Security Review: Securing Britain in an Age of Uncertainty, 19 Oct 2010 | https://www.gov.uk/government/publications/the-strategic-defence-and-security-review-securing-britain-in-an-age-of-uncertainty | 2026-11-12 | Confirmed |
| 81 | The White House (archived), CNCI summary page (national-initiative) | https://obamawhitehouse.archives.gov/issues/foreign-policy/cybersecurity/national-initiative | 2026-11-12 | Confirmed (content); date not checked |
| 82 | Heartland Payment Systems, Exhibit 99.1 on the Visa settlement, 8 Jan 2010 (SEC EDGAR; as cited by the E-Commerce Threats study, not reopened) | `https://www.sec.gov/Archives/edgar/data/0001144354/000119312510003149/dex991.htm` | 2026-11-12 | Inferred (carried from the home study) |
| 83 | TeamStarWolf Intelligence Hub, feed (used as a map) | https://teamstarwolf.github.io/intelligence-hub/data/feed.json | 2026-11-12 | Confirmed (as feed data) |
| 84 | TeamStarWolf library, ATT&CK data files (`data/attack/`, `data/attack/ics/`) | https://github.com/TeamStarWolf/TeamStarWolf/tree/main/data/attack | 2026-11-12; 2026-11-13 | Confirmed; Demonstrated |
| 85 | TeamStarWolf library, weakness and countermeasure data (`data/weaknesses/capec.jsonl`, `cwe.jsonl`, `data/attack/technique_to_d3fend.jsonl`) | https://github.com/TeamStarWolf/TeamStarWolf/tree/main/data/weaknesses | 2026-11-12; 2026-11-13 | Demonstrated |
| 86 | TeamStarWolf library, `mitre/` page tree (technique, group, software, campaign, CAPEC, D3FEND and mitigation pages) | https://github.com/TeamStarWolf/TeamStarWolf/tree/main/mitre | 2026-11-12; 2026-11-13 | Demonstrated |
| 87 | TeamStarWolf library, case studies on main (home studies named in the text; Notable Incidents line 84 as flagged by the Hacker and the State study) | https://github.com/TeamStarWolf/TeamStarWolf/tree/main/case-studies | 2026-11-12; 2026-11-13 | Confirmed (for the fact that a study is the home and for the facts it carries from its own sources) |
| 88 | TeamStarWolf library, chronicle Navigator layers (`navigator/library-layers/chronicle-2016.json` and the later years) | https://github.com/TeamStarWolf/TeamStarWolf/tree/main/navigator/library-layers | 2026-11-13 | Demonstrated |

*© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.*

*© The MITRE Corporation. Includes material from the Common Weakness Enumeration (CWE™), used under the CWE Terms of Use. https://cwe.mitre.org/*

*© The MITRE Corporation. Includes material from the Common Attack Pattern Enumeration and Classification (CAPEC™), used under the CAPEC Terms of Use. https://capec.mitre.org/*

*© The MITRE Corporation. Includes material from MITRE D3FEND™, used under the D3FEND Terms of Use. https://d3fend.mitre.org/*

*The terms for every MITRE dataset used here are recorded in [THIRD_PARTY_NOTICES.md](/THIRD_PARTY_NOTICES.md).*

## Related references

- [Notable Incidents](/NOTABLE_INCIDENTS.md), [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [CVE Reference](/CVE_REFERENCE.md)
- [CWE Reference](/CWE_REFERENCE.md), [CAPEC Reference](/CAPEC_REFERENCE.md), [D3FEND Reference](/D3FEND_REFERENCE.md), [Cryptography](/CRYPTOGRAPHY_REFERENCE.md), [Browser Security](/BROWSER_SECURITY_REFERENCE.md), [Email Security](/EMAIL_SECURITY_REFERENCE.md), [GRC and Compliance](/GRC_COMPLIANCE_REFERENCE.md), [Vulnerability Management](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [Incident Response](/INCIDENT_RESPONSE_REFERENCE.md), [ICS/OT Security](/ICS_OT_SECURITY_REFERENCE.md)
- Home studies: [The Zero-Day Trade and Its Fallout](/case-studies/ZERO_DAY_MARKET_EVENTS.md); [Stuxnet](/case-studies/STUXNET.md); [Four Books on Cybercrime](/case-studies/CYBERCRIME_FOUR_BOOKS.md); [E-Commerce Threats](/case-studies/ECOMMERCE_THREATS.md); [China-attributed threat actors](/case-studies/THREAT_ACTORS_CHINA.md); [United States-attributed threat actors](/case-studies/THREAT_ACTORS_UNITED_STATES.md); [The Hacker and the State](/case-studies/HACKER_AND_THE_STATE_CASES.md); [APT41](/case-studies/APT41_PUBLIC_RECORD.md); [ICS attacks and advisories](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md); [Log4Shell](/case-studies/LOG4SHELL.md); [SolarWinds SUNBURST](/case-studies/SOLARWINDS_SUNBURST.md); [npm supply-chain attacks](/case-studies/NPM_SUPPLY_CHAIN_ATTACKS.md); [Hugging Face supply chain](/case-studies/HUGGING_FACE_SUPPLY_CHAIN.md)
- Series: [1993](/case-studies/CHRONICLE_1993.md), [1994](/case-studies/CHRONICLE_1994.md), [1995](/case-studies/CHRONICLE_1995.md), [1996](/case-studies/CHRONICLE_1996.md), [1997](/case-studies/CHRONICLE_1997.md), [1998](/case-studies/CHRONICLE_1998.md), [1999](/case-studies/CHRONICLE_1999.md), [2000](/case-studies/CHRONICLE_2000.md), [2001](/case-studies/CHRONICLE_2001.md), [2002](/case-studies/CHRONICLE_2002.md), [2003](/case-studies/CHRONICLE_2003.md), [2004](/case-studies/CHRONICLE_2004.md), [2005](/case-studies/CHRONICLE_2005.md), [2006](/case-studies/CHRONICLE_2006.md), [2007](/case-studies/CHRONICLE_2007.md), [2016](/case-studies/CHRONICLE_2016.md), [2017](/case-studies/CHRONICLE_2017.md), [2018](/case-studies/CHRONICLE_2018.md), [2019](/case-studies/CHRONICLE_2019.md), [2020](/case-studies/CHRONICLE_2020.md), [2021](/case-studies/CHRONICLE_2021.md), [2022](/case-studies/CHRONICLE_2022.md), [2023](/case-studies/CHRONICLE_2023.md), [2024](/case-studies/CHRONICLE_2024.md), [2025](/case-studies/CHRONICLE_2025.md), [2026](/case-studies/CHRONICLE_2026.md)
- Techniques: [T1189 Drive-by Compromise](/mitre/techniques/T1189.md), [T1203 Exploitation for Client Execution](/mitre/techniques/T1203.md), [T1566.001 Spearphishing Attachment](/mitre/techniques/T1566-001.md), [T1566.002 Spearphishing Link](/mitre/techniques/T1566-002.md), [T1566.003 Spearphishing via Service](/mitre/techniques/T1566-003.md), [T1593.001 Social Media](/mitre/techniques/T1593-001.md), [T1091 Replication Through Removable Media](/mitre/techniques/T1091.md), [T1210 Exploitation of Remote Services](/mitre/techniques/T1210.md), [T1068 Exploitation for Privilege Escalation](/mitre/techniques/T1068.md), [T1014 Rootkit](/mitre/techniques/T1014.md), [T1553.002 Code Signing](/mitre/techniques/T1553-002.md), [T1078.001 Default Accounts](/mitre/techniques/T1078-001.md), [T1190 Exploit Public-Facing Application](/mitre/techniques/T1190.md), [T1102 Web Service](/mitre/techniques/T1102.md), [T1539 Steal Web Session Cookie](/mitre/techniques/T1539.md), [T1110 Brute Force](/mitre/techniques/T1110.md), [T1505.003 Web Shell](/mitre/techniques/T1505-003.md), [T1040 Network Sniffing](/mitre/techniques/T1040.md), [T1566 Phishing](/mitre/techniques/T1566.md), [T1056.001 Keylogging](/mitre/techniques/T1056-001.md), [T1657 Financial Theft](/mitre/techniques/T1657.md), [T1498 Network Denial of Service](/mitre/techniques/T1498.md), [T1574.001 DLL](/mitre/techniques/T1574-001.md); the full list is in the Part 9 table
- CAPEC: [CAPEC-21](/mitre/capec/CAPEC-21.md), [CAPEC-31](/mitre/capec/CAPEC-31.md), [CAPEC-55](/mitre/capec/CAPEC-55.md), [CAPEC-62](/mitre/capec/CAPEC-62.md), [CAPEC-63](/mitre/capec/CAPEC-63.md), [CAPEC-65](/mitre/capec/CAPEC-65.md), [CAPEC-66](/mitre/capec/CAPEC-66.md), [CAPEC-68](/mitre/capec/CAPEC-68.md), [CAPEC-70](/mitre/capec/CAPEC-70.md), [CAPEC-94](/mitre/capec/CAPEC-94.md), [CAPEC-98](/mitre/capec/CAPEC-98.md), [CAPEC-100](/mitre/capec/CAPEC-100.md), [CAPEC-102](/mitre/capec/CAPEC-102.md), [CAPEC-112](/mitre/capec/CAPEC-112.md), [CAPEC-126](/mitre/capec/CAPEC-126.md), [CAPEC-163](/mitre/capec/CAPEC-163.md), [CAPEC-191](/mitre/capec/CAPEC-191.md), [CAPEC-457](/mitre/capec/CAPEC-457.md), [CAPEC-471](/mitre/capec/CAPEC-471.md), [CAPEC-552](/mitre/capec/CAPEC-552.md), [CAPEC-555](/mitre/capec/CAPEC-555.md), [CAPEC-560](/mitre/capec/CAPEC-560.md), [CAPEC-561](/mitre/capec/CAPEC-561.md), [CAPEC-562](/mitre/capec/CAPEC-562.md), [CAPEC-568](/mitre/capec/CAPEC-568.md), [CAPEC-641](/mitre/capec/CAPEC-641.md), [CAPEC-644](/mitre/capec/CAPEC-644.md), [CAPEC-650](/mitre/capec/CAPEC-650.md)
- Groups, software and campaigns: Elderwood [G0066](/mitre/groups/G0066.md); Axiom [G0001](/mitre/groups/G0001.md); Hydraq [S0203](/mitre/software/S0203.md); PoisonIvy [S0012](/mitre/software/S0012.md); Stuxnet [S0603](/mitre/software/S0603.md); Flame [S0143](/mitre/software/S0143.md); ASPXSpy [S0073](/mitre/software/S0073.md); at [S0110](/mitre/software/S0110.md); gsecdump [S0008](/mitre/software/S0008.md); PsExec [S0029](/mitre/software/S0029.md); zwShell [S0350](/mitre/software/S0350.md); Night Dragon [C0002](/mitre/campaigns/C0002.md); Operation Dust Storm [C0016](/mitre/campaigns/C0016.md)
- [Navigator layers](/navigator/index.md), including this study's layers, [chronicle-2010.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/chronicle-2010.json) and [chronicle-2010-ics.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/case-studies/chronicle-2010-ics.json)
