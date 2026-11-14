# The Year 2008 in Intrusions: A Dated Record

*A TeamStarWolf case study. Published 13 November 2026; every source checked as of that date.*

[All case studies](/case-studies/README.md) · Related: [Notable Incidents](/NOTABLE_INCIDENTS.md), [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [CVE Reference](/CVE_REFERENCE.md), [Cryptography](/CRYPTOGRAPHY_REFERENCE.md), [GRC and Compliance](/GRC_COMPLIANCE_REFERENCE.md), [Incident Response](/INCIDENT_RESPONSE_REFERENCE.md), [Vulnerability Management](/VULNERABILITY_MANAGEMENT_REFERENCE.md) · Home studies for events summarized here: [E-Commerce Threats](/case-studies/ECOMMERCE_THREATS.md) (the Gonzalez ring, Heartland, Wyndham and PCI DSS), [Four Books on Cybercrime](/case-studies/CYBERCRIME_FOUR_BOOKS.md) (the Walker and Gembe indictment and the DarkMarket sting), [Stuxnet](/case-studies/STUXNET.md) (early Stuxnet components and MS08-067), [United States-attributed threat actors](/case-studies/THREAT_ACTORS_UNITED_STATES.md) (Equation, Fanny, Regin and the Lamberts) and [The Hacker and the State](/case-studies/HACKER_AND_THE_STATE_CASES.md) (Regin), [Russia-attributed threat actors](/case-studies/THREAT_ACTORS_RUSSIA.md) (APT28, APT29 and Turla), [China-attributed threat actors](/case-studies/THREAT_ACTORS_CHINA.md) (Axiom and BRONZE BUTLER) · Series: [The Year 2004 in Intrusions](/case-studies/CHRONICLE_2004.md), [The Year 2005 in Intrusions](/case-studies/CHRONICLE_2005.md), [The Year 2016 in Intrusions](/case-studies/CHRONICLE_2016.md) and the other years in the [case studies index](/case-studies/README.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Threat intelligence analysts, security historians, vulnerability management, payment-card and network teams and anyone who wants the history behind current threats

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Beginner to intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 65 min (15,026 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want a dated record of the intrusions of 2008, you need MS08-067, the Debian, DNS and MD5 foundation flaws, the SQL injection wave and the card-theft cases side by side with Buckshot Yankee, Georgia and the operations later reports date to 2008, the policy and standards that followed, or you want the defender lessons that still apply

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [Part 2: the vulnerability record](#part-2-the-vulnerability-record), [Part 4: the state record](#part-4-the-state-record)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Notable Incidents](/NOTABLE_INCIDENTS.md), [E-Commerce Threats](/case-studies/ECOMMERCE_THREATS.md), [Vulnerability Management](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [The Year 2005 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2005.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive summary

The year's defining technical event came late. On 23 October Microsoft shipped MS08-067 outside its monthly cycle to fix a flaw in the Windows Server service, CVE-2008-4250, and warned that it "could be used in the crafting of a wormable exploit" (Confirmed [16]). The same day CERT/CC said exploit code was public and the flaw was "being currently exploited in the wild", and NVD records a trojan, Gimmiv.A, exploiting it in October 2008 (Confirmed [17][18]). ATT&CK's entry for the Conficker worm (also called Kido and Downadup) says it was first detected in October 2008 and spread through MS08-067; ATT&CK draws that date from secondary sources; accounts giving a different month were not checked here (Reported [20]). Microsoft's own support article says Conficker spread through the flaw, network shares and AutoPlay, and lists symptoms such as tripped account lockouts and disabled Automatic Updates, BITS, Windows Defender and Error Reporting services (Confirmed [21]). CISA did not add CVE-2008-4250 to its Known Exploited Vulnerabilities catalog until 20 May 2026 (Confirmed [19]).

The working attack surface was otherwise the web site, the browser and the document. On 24 June Microsoft warned of an escalating wave of SQL injection against ASP and ASP.NET sites that did not follow secure coding practices, and said plainly that no product flaw was involved; compromised sites could forward their visitors to malicious sites that installed malware (Confirmed [7]). Adobe Reader's util.printf() flaw was public on 4 November and Internet Explorer's data binding flaw on 9 December; Microsoft's out-of-band fix for Internet Explorer, MS08-078, said the flaw was being exploited when it shipped on 17 December (Confirmed [22][25][26]).

Two flaws went to the foundations. On 13 May Debian disclosed that a Debian-specific change had made OpenSSL's random number generator predictable, so that SSH, OpenVPN, DNSSEC and X.509 keys generated on affected systems might be guessable, and told users to upgrade and then regenerate all key material (Confirmed [3][5]). On 8 July CERT/CC published a coordinated multi-vendor note on DNS cache poisoning, CVE-2008-1447, and Microsoft shipped MS08-037 the same day; other vendors, BIND among them, patched from July to September (Confirmed [8][9][10]). On 30 December researchers showed at 25C3 that an MD5 collision could yield a rogue certificate authority certificate trusted by common browsers; Microsoft said it knew of no active attacks (Confirmed [28][30]).

The card-theft record grew all year and was mostly written afterwards. Hannaford announced a breach on 17 March after Visa told it of a problem on 27 February, as the First Circuit later recited the plaintiffs' allegations (Confirmed as alleged [56]). On 5 August the Justice Department charged eleven people, including Albert Gonzalez, over intrusions at nine US retailers and more than 40 million stolen card numbers, and called it the largest hacking and identity theft case it had prosecuted (Confirmed [51]). Heartland Payment Systems said in January 2009 that it had been breached "within its processing system in 2008" (Confirmed [12]). The FBI closed a two-year undercover operation inside the DarkMarket carding forum in October with 56 arrests worldwide (Confirmed [15]). The [E-Commerce Threats](/case-studies/ECOMMERCE_THREATS.md) study is the home for the Gonzalez ring, Heartland and Wyndham; this chronicle records their 2008 dates.

The state record was almost entirely written later. A Deputy Secretary of Defense wrote in 2010 that in 2008 an infected flash drive put code "placed there by a foreign intelligence agency" onto US Central Command networks, the most significant breach of US military computers ever, and that the response was Operation Buckshot Yankee (Confirmed [23]). ATT&CK says the Agent.btz worm "reportedly infected U.S. military networks in 2008"; tying it to Buckshot Yankee is this study's inference (Reported [24]). Cyber attacks on Georgia ran from 8 to 28 August alongside the armed conflict, with denial of service, defacement and an exploited SQL flaw; the NATO-accredited CCDCOE found organised Russian hacker groups most likely behind the exploit attacks but no evident link to the Russian administration (Confirmed [38]). Investigators in Dharamsala found the Office of His Holiness the Dalai Lama compromised through e-mail lures (Confirmed [35]). Vendor reports from 2014 to 2017 date Equation's Fanny worm, a Regin operation against a GSM network and the Lamberts toolkit to 2008, and ATT&CK says some Stuxnet components were in use as early as November 2008 (Confirmed [39][42][43][41]). None of those reports was public in 2008.

Policy moved fast. The White House's national cybersecurity initiative, CNCI, began in January, NATO adopted its first cyber defence policy the same month, CCDCOE was founded in May, FERC approved eight NERC CIP reliability standards, and Congress amended the computer fraud statute in September (Confirmed [1][66][67][60][63]). CWE reached version 1.0, PCI DSS reached 1.2, TLS reached 1.2, and NIST published new incident handling and security testing guides (Confirmed [59][13][69][68][71]).

This study records the year by date. It is built only from sources opened on 12 November 2026 (source 6 on 13 November) and checks of the library's data run on 13 November 2026, and is checked as of 13 November 2026.

### Key facts at a glance

| Field | Value |
|---|---|
| Period | 1 January to 31 December 2008, plus the records that open, close or explain a 2008 event: Hannaford's intrusion from December 2007, Heartland's January 2009 filing, the GhostNet and Cambridge reports (2009), the Lynn article (2010), the CCDCOE legal analysis (2010), the Hannaford and Wyndham appeals (2011 and 2015), vendor reports from 2014 to 2017 and KEV additions from 2022 to 2026 |
| Wormable flaw | MS08-067 (CVE-2008-4250), out of band on 23 Oct; exploited in the wild per CERT/CC; Gimmiv.A per NVD; Conficker first detected in Oct per ATT&CK (Reported); KEV added 20 May 2026 (Confirmed [16][17][18][19]; Reported [20]) |
| Foundations | Debian OpenSSL RNG (CVE-2008-0166, 13 May); DNS cache poisoning (CVE-2008-1447, 8 Jul); MD5 rogue CA research (30 Dec) (Confirmed [3][5][8][28]) |
| Web and client exploitation | Mass SQL injection on ASP and ASP.NET sites (Advisory 954462, 24 Jun); Adobe util.printf (CVE-2008-2992, 4 Nov); Internet Explorer data binding (CVE-2008-4844, public 9 Dec, MS08-078 on 17 Dec); Flash clickjacking advisory (7 Oct) (Confirmed [7][22][25][26][73]) |
| KEV tail | Six CVE-2008 ids in KEV (catalog 2026.11.10), added 2022 to 2026 (Confirmed [19]) |
| Card theft | Hannaford announced 17 Mar (up to 4.2 million cards, as alleged); Wyndham's first intrusion in Apr (as alleged); Dave & Buster's charges unsealed 12 May; Gonzalez ring charged 5 Aug (more than 40 million cards); Heartland breached during 2008 (disclosed 20 Jan 2009) (Confirmed [56][57][49][51][12]) |
| Prosecutions and takedowns | Ralsky spam indictment (3 Jan); US and Romania card fraud cases (19 May); botnet sale charge (21 Aug); Palin e-mail access charge (8 Oct); Walker and Gembe DDoS indictment (2 Oct); DarkMarket sting, 56 arrests (20 Oct); McKinnon's extradition appeal dismissed (30 Jul) (Confirmed [48][50][52][53][14][15][54]) |
| State and politically timed attacks | Buckshot Yankee (2008, written 2010); OHHDL compromise (investigated Sep); Georgia (8 to 28 Aug); RFE/RL Belarus (26 to 28 Apr); Lithuania (28 Jun to 2 Jul) (Confirmed [23][35][38]) |
| Written later | Fanny compiled Jul 2008; Regin's GSM log Apr to May 2008; the Lamberts since at least 2008; Stuxnet components from Nov 2008; APT29, Axiom, BRONZE BUTLER and FIN5 since at least 2008, no 2008 operation named (Confirmed [39][42][43][41][44][45][46]; Demonstrated [76]) |
| Infrastructure and industry | YouTube prefix hijack (24 Feb); FERC Order No. 706 (7 Feb); FERC nuclear proposal (25 Sep); OMB DNSSEC mandate (Aug); Hatch nuclear plant shutdown after a software update (Reported); EU critical infrastructure directive (8 Dec) (Confirmed [2][60][61][70][65]; Reported [62]) |
| Law and policy | CNCI (Jan); NATO's first cyber defence policy (Jan); CCDCOE founded (14 May); FTC TJX order (27 Mar proposed, 1 Aug final); PL 110-326 (26 Sep); CSIS commission report (8 Dec) (Confirmed [1][66][67][58][63][64]) |
| Standards | NVD begins CWE mappings (12 Mar); SP 800-61 Rev. 1 (Mar); TLS 1.2 (Aug); SP 800-115 (Sep); CWE 1.0 (9 Sep); PCI DSS 1.2 (1 Oct); Chrome sandbox post (2 Oct); Microsoft Exploitability Index (Oct) (Confirmed [59][68][69][71][13][72][74]) |
| This study's MITRE binding | 33 ATT&CK Enterprise techniques in 39 technique-tactic entries: 17 listed by ATT&CK for Conficker (S0608) and Agent.btz (S0092), 15 described by a primary and assigned here, one inferred; three ATT&CK for ICS techniques ATT&CK lists for Conficker, not tied to a 2008 event; Stuxnet, Regin, Green Lambert, Equation, APT29, Axiom, BRONZE BUTLER, FIN5, APT28 and Turla bound with dating caveats; no campaign object; NVD's CWE-338, CWE-331, CWE-94, CWE-119, CWE-787, CWE-399 and CWE-352 plus study-class CWEs; CAPEC and D3FEND pairings from the library's data; one Enterprise Navigator layer (Part 7) |

### Key findings

- **A wormable Windows flaw defined the year's end.** Microsoft broke its monthly cycle for MS08-067, CERT/CC reported exploitation the same day, and Microsoft's later support article describes Conficker spreading through it, through shares and through AutoPlay (Confirmed [16][17][21]).
- **The biggest web threat was not a product bug.** Microsoft said the 2008 SQL injection wave exploited sites that did not validate input, not a flaw in its products, which is why it has no CVE id (Confirmed [7]; the CVE consequence is Inferred).
- **Patching was not enough for the Debian flaw.** Debian told users to upgrade and then regenerate all key material, and to treat every DSA key used on an affected system as compromised (Confirmed [5]).
- **DNS was mitigated, not fixed.** US-CERT said per-query source port randomization makes cache poisoning less practical but is not a full fix, and vendors named DNSSEC as the only full solution (Confirmed [8]). OMB ordered DNSSEC on .gov by January 2009 (Confirmed [70]).
- **The card networks were the breach sensor.** Visa told Hannaford, as alleged, and Visa and MasterCard told Heartland, before either company found its own intrusion (Confirmed as alleged [56]; Confirmed [12]; the pattern is Inferred).
- **The year's most serious military breach is known from an official's article published two years later, which names neither malware nor a country.** Lynn's article says "a foreign intelligence agency"; the Agent.btz name comes from ATT&CK's "reportedly" and the Turla link is called unproven by Kaspersky (Confirmed [23][33]; Reported [24]).
- **Georgia was a pattern, not a first.** RFE/RL's Belarus service was flooded in April and more than 300 Lithuanian sites were defaced in June and July, each with an origin CCDCOE calls undetermined, before the August attacks on Georgia (Confirmed [38]).
- **The capable operations were invisible.** Fanny, Regin's GSM log, the Lamberts' tools and early Stuxnet components all date to 2008 in reports published from 2014 to 2017, the Regin and Lamberts reports name no country, and ATT&CK gives Equation and Stuxnet no sponsor or group (Confirmed [39][42][43][41][40]).
- **2008 built the vocabulary later years use.** NVD's first CWE mappings, CWE 1.0, the first advisory carrying a CWE id, PCI DSS 1.2, TLS 1.2, SP 800-61 Rev. 1 and SP 800-115 all date from this year (Confirmed [59][13][69][68][71]).

### Top recommendations

1. **Treat a wormable network-service flaw as an emergency.** MS08-067 shipped out of band, was already exploited, and Microsoft's workarounds were to block TCP 139 and 445 at the firewall and disable the Server and Computer Browser services (Confirmed [16][17][19]).
2. **After a key-generation flaw, rotate the keys, not just the package.** Debian's advice was to upgrade and then regenerate every key made on an affected system (Confirmed [5]).
3. **Fix injection in the code you own.** Microsoft's 2008 advisory pointed site owners to a scanner, a request filter and a source code analyzer because the flaw was in their pages, not in Windows (Confirmed [7]). The library's [CWE reference](/CWE_REFERENCE.md) covers CWE-89 (Inferred).
4. **Randomize resolver source ports, check the NAT in front of them, and plan for DNSSEC.** Those are US-CERT's mitigations for CVE-2008-1447 (Confirmed [8]).
5. **Control removable media and AutoPlay.** Agent.btz, Fanny and Conficker all spread through removable drives in the record (Confirmed [21][39]; Reported [24]).
6. **Keep store and hotel networks apart from the core.** The Gonzalez ring was charged with wardriving into retailers' wireless networks, and the FTC alleged that Wyndham's April 2008 intruders came in through one hotel's network connected to Wyndham's own (Confirmed [51][57]).
7. **Limit guessing against administrator accounts.** The FTC alleged that Wyndham's intruders brute-forced an administrator account; Conficker's symptoms include tripped lockout policies (Confirmed [57][21]).
8. **Build detection so the card brand is not your sensor.** Hannaford, as alleged, and Heartland both learned of their breaches from the payment networks (Confirmed as alleged [56]; Confirmed [12]; Inferred).
9. **Retire weak hashes in your PKI.** The rogue CA researchers recommended that CAs drop MD5 and randomize serial numbers, and Microsoft urged CAs to stop signing with MD5 (Confirmed [29][30]).
10. **Arrange denial-of-service and hosting continuity before you need it.** Georgia moved services abroad, Estonia hosted its foreign ministry site and Poland's President hosted its press releases (Confirmed [38]).
11. **Do not read KEV dates as event dates.** CVE-2008-4250 entered KEV in 2026 and CVE-2008-4128 in July 2026 (Confirmed [19]).
12. **Make account recovery as strong as the password.** The 2008 indictment over a governor's personal e-mail account alleges access by resetting the password through its security questions (Confirmed as alleged [53]).

## Scope and method

This study covers intrusions, vulnerabilities, malware, card theft, prosecutions, state operations, internet infrastructure, industrial security, regulation, standards and policy dated to 2008, plus the later records that open, close or explain a 2008 event. It follows the method of the [case studies collection](/case-studies/README.md): primary sources first, every claim graded, and numbers given as the source states them. Sources were opened on 12 November 2026 (source 6 on 13 November), and the library data checks were run on 13 November 2026.

| Grade | Meaning in this study |
|---|---|
| Confirmed | The primary record was opened and states the fact: a vendor bulletin or advisory, a CERT/CC note, a US-CERT or CISA alert, an NVD record, the KEV catalog, a Debian security announcement, a Justice Department, US Attorney or FBI release, a court opinion, an SEC filing, an FTC case page, a statute, regulation or Federal Register notice, an OMB memorandum, a NIST, IETF, MITRE, PCI SSC, NATO or CCDCOE record, an official's own published statement, a researchers' or vendor's report stated as its own finding, a live ATT&CK page, or a library study, only for the fact that it is the home for an event |
| Reported | Only a secondary source supports the fact, or a source relays a claim that is someone else's: Network World on a book, a victim government's statement or analysts quoted by CCDCOE, NIST relaying a news report, EFF as counsel's case page, ThreatExpert's link to the Pentagon incident, and ATT&CK dates that ATT&CK draws from secondary sources. The source is named in the text |
| Demonstrated | A check this study ran itself and saw the result: id, name, tactic and page checks in the library's data files and `mitre/` page tree |
| Inferred | The study's own reading, labelled where it appears. Every ATT&CK, CAPEC and D3FEND id bound to a 2008 event is Inferred as to the binding unless ATT&CK lists it for the object, and so is every CWE that NVD does not list |

Indictments, complaints and the facts that appeals courts recite from a complaint are allegations; where this study cites one, the record confirms that the allegation was made, not that it was proven. Company filings are the company's own account, and vendor attributions are those vendors' assessments, not government findings.

Limits a reader should know:

- **CVE existed; ATT&CK and KEV did not.** The CVE list predates 2008, so every 2008 product flaw here carries a CVE id. ATT&CK came years later, so no 2008 record carries an ATT&CK id, and every technique in Part 7 is a later mapping: either one ATT&CK records for an object it dates to 2008, or this study's own reading (Inferred). KEV's six CVE-2008 entries were added from 2022 to 2026 (Confirmed [19]).
- **CWE arrived during the year.** NVD began using CWE mappings in March and CWE version 1.0 was posted on 9 September (Confirmed [59]). The CWE ids NVD now lists for flaws disclosed earlier in 2008 may have been assigned after the fact (Inferred).
- **Some events have no id of any kind.** The YouTube prefix hijack was a routing incident with no CVE and no ATT&CK technique, the SQL injection wave had no product flaw, and the MD5 rogue CA research carries no CVE (Confirmed [2][7][31]).
- **What was not checked.** No primary was opened for: Hannaford's own March 2008 notice; the 2009 Gonzalez indictment naming Heartland, Hannaford and 7-Eleven; the RBS WorldPay ATM cash-out of November 2008; the McColo hosting takedown; the Conficker Working Group's report; Microsoft's malware encyclopedia entry for Conficker; McAfee's Operation Shady RAT report; any Georgian government or US-CCU primary on August 2008; the Georgian foreign ministry's own 11 August statement; CCDCOE's 2008 Georgia legal lessons paper; Lynn's article past its opening section; Adobe's APSB08-19 fix bulletin; the release date of the SANS/MITRE Top 25; Microsoft's MAPP launch date; ISO/IEC 27005:2008; the body of the Chrome sandbox post; CAPEC's 2008 release history; the 2008 presidential campaign intrusions; the Lori Drew verdict; the Storm, Srizbi and Koobface botnets; Pwn2Own 2008; and any full-year NVD count. They are left out or marked "not checked" where they touch a verified fact. Their absence here is not evidence that nothing happened.

## Part 1: the year as a dated timeline

One row per event or report. The date is the event date where the source gives one, otherwise the publication date. Rows marked "frame" or "boundary" open or close a 2008 event.

| Date | Event | Thread | Sector | Grade | Sources |
|---|---|---|---|---|---|
| 2001-02-01 to 2002-03-19 (frame) | Conduct alleged in the US extradition request for Gary McKinnon: unauthorized access to 97 US Government computers | Law | Government | Confirmed (as alleged) | [54] |
| 2006-09-17 (frame) | Earliest date from which keys generated on affected Debian systems may be weak, per CERT/CC | Vulnerability | Cross-sector | Confirmed | [3] |
| 2007 (frame) | Kaspersky dates Agent.btz's origins to 2007 | State | Defense | Confirmed (vendor's analysis) | [33] |
| 2007-12-07 (frame) | Hannaford's payment processing system breached as early as this date, as alleged | Card theft | Retail (grocery) | Confirmed (as alleged) | [56] |
| 2008-01 | President Bush launches the national cybersecurity initiative (CNCI) in NSPD-54/HSPD-23 | Policy | Government | Confirmed | [1] |
| 2008-01 | NATO approves its first Policy on Cyber Defence | Policy | Defense | Confirmed | [66] |
| 2008-01-03 | Indictment unsealed in Detroit charging Alan Ralsky and ten others in a spam and stock fraud scheme | Crime | Financial, internet | Confirmed (as alleged) | [48] |
| 2008-02-01 | A GrayFish installer compiled, per Kaspersky. Home: [United States-attributed threat actors](/case-studies/THREAT_ACTORS_UNITED_STATES.md) | State | Unknown | Confirmed (vendor's analysis) | [39] |
| 2008-02-07 | FERC Order No. 706 published: eight NERC CIP standards approved (effective 7 Apr) | Regulation | Energy | Confirmed | [60] |
| 2008-02-24 | Pakistan Telecom announces YouTube's 208.65.153.0/24 at 18:47 UTC; PCCW Global propagates it; YouTube counters at 20:07 and 20:18; PCCW withdraws at 21:01 | Infrastructure | Telecom, internet | Confirmed | [2] |
| 2008-02-27 | Visa notifies Hannaford of a problem | Card theft | Retail (grocery) | Confirmed (as alleged) | [56] |
| 2008-03 | NIST SP 800-61 Rev. 1, incident handling guide | Standards | Cross-sector | Confirmed | [68] |
| 2008-03-08 to 2008-03-10 | Hannaford finds the means of access (8 Mar) and contains the breach (10 Mar) | Card theft | Retail (grocery) | Confirmed (as alleged) | [56] |
| 2008-03-12 | NVD begins using CWE mappings; Dave & Buster's indictment returned in E.D.N.Y. (unsealed 12 May) | Standards; Crime | Cross-sector; hospitality | Confirmed | [59][49] |
| 2008-03-17 | Hannaford announces the breach: more than 270 stores, about 1,800 fraud cases already reported | Card theft | Retail (grocery) | Confirmed (as alleged) | [56] |
| 2008-03-25 | A Core Security advisory becomes the first advisory to carry a CWE id (reported in CWE news on 26 Mar) | Standards | Cross-sector | Confirmed | [59] |
| 2008-03-27 | FTC announces the proposed TJX consent order with separate actions against Reed Elsevier and Seisint | Regulation | Retail, data brokers | Confirmed | [58] |
| 2008-04 | Wyndham's first intrusion, through a Phoenix hotel's network, as alleged by the FTC. Home: [E-Commerce Threats](/case-studies/ECOMMERCE_THREATS.md) | Card theft | Hospitality | Confirmed (as alleged) | [57] |
| 2008-04-25 to 2008-05-27 | Regin's decoded GSM base station controller log, commands on 136 cells | State | Telecom | Confirmed (vendor's analysis) | [42] |
| 2008-04-26 to 2008-04-28 | DDoS on RFE/RL's Belarus service, seven other RFE/RL sites and independent Belarusian news sites | State or hacktivist (undetermined) | Media | Confirmed | [38] |
| 2008-05-12 | Dave & Buster's charges unsealed: two foreign nationals indicted and Albert Gonzalez charged by complaint over cash register intrusions at 11 restaurants | Crime | Hospitality | Confirmed (as alleged) | [49] |
| 2008-05-13 | Debian DSA-1571-1: predictable OpenSSL random number generator (CVE-2008-0166); NVD published the same day | Vulnerability | Cross-sector | Confirmed | [5][4] |
| 2008-05-14 | CCDCOE established in Tallinn | Policy | Defense | Confirmed | [67] |
| 2008-05-15 | CERT/CC publishes VU#925211 on the Debian and Ubuntu OpenSSL flaw (public 13 May) | Vulnerability | Cross-sector | Confirmed | [3] |
| 2008-05-19 | 38 people in the US and Romania charged in two related computer and card fraud cases, announced in Bucharest | Crime | Financial | Confirmed (as alleged) | [50] |
| 2008-06-24 | Microsoft Security Advisory 954462: rise in SQL injection on ASP and ASP.NET sites | Web exploitation | Cross-sector | Confirmed | [7] |
| 2008-06-28 to 2008-07-02 | More than 300 Lithuanian websites defaced with pro-Soviet symbols after the insignia ban | Hacktivism (undetermined) | Private sector, government | Confirmed | [38] |
| 2008-07-08 | CERT/CC VU#800113 and Microsoft MS08-037: coordinated DNS cache poisoning fixes (CVE-2008-1447) | Vulnerability | Internet infrastructure | Confirmed | [8][9][10] |
| 2008-07-28 | Equation's Fanny worm compiled (timestamp), per Kaspersky. Home: [United States-attributed threat actors](/case-studies/THREAT_ACTORS_UNITED_STATES.md) | State | Unknown | Confirmed (vendor's analysis) | [39] |
| 2008-07-30 | House of Lords dismisses McKinnon's extradition appeal | Law | Government | Confirmed | [54] |
| 2008-08 | RFC 5246, TLS 1.2 | Standards | Cross-sector | Confirmed | [69] |
| 2008-08-01 | FTC's final TJX Decision and Order | Regulation | Retail | Confirmed | [58] |
| 2008-08-05 | Eleven charged over nine US retailers and more than 40 million card numbers; Gonzalez indicted in Boston. Home: [E-Commerce Threats](/case-studies/ECOMMERCE_THREATS.md) | Crime | Retail | Confirmed (as alleged) | [51] |
| 2008-08-08 to 2008-08-28 | Cyber attacks on Georgia during the South Ossetia conflict; Shadowserver logs the first incidents on 8 Aug | State or hacktivist (undetermined) | Government, media, finance | Confirmed | [38] |
| 2008-08-09 to 2008-08-19 | A federal court order stops, then frees, three MIT students' DEF CON talk on transit fare-system weaknesses | Law | Transportation | Reported | [55] |
| 2008-08-11 | Georgia's foreign ministry calls the attacks "a cyber warfare campaign by Russia"; the President's site defaced and under sustained DDoS | State | Government | Reported (statement); Confirmed (defacement and DDoS) | [38] |
| 2008-08-21 | A Brazilian national charged in E.D. La. with conspiring to sell a botnet; more than 100,000 computers damaged, as alleged | Crime | Cross-sector | Confirmed (as alleged) | [52] |
| 2008-08-22 | OMB M-08-23: DNSSEC on .gov by January 2009 and on all federal systems by December 2009 | Policy | Government | Confirmed | [70] |
| 2008-09 | NIST SP 800-115, security testing and assessment guide | Standards | Cross-sector | Confirmed | [71] |
| 2008-09 | Nagaraja travels to Dharamsala to help investigate the OHHDL compromise | State | Government (exile), NGO | Confirmed | [35] |
| 2008-09-09 | CWE Version 1.0 posted (1.0.1 on 14 Oct, 1.1 on 25 Nov) | Standards | Cross-sector | Confirmed | [59] |
| 2008-09-16 | A governor's personal e-mail account accessed by resetting the password through security questions, as alleged | Crime | Government (personal account) | Confirmed (as alleged) | [53] |
| 2008-09-25 | FERC proposes that non-NRC-regulated nuclear plant facilities fall under the CIP standards | Regulation | Energy (nuclear) | Confirmed | [61] |
| 2008-09-26 | Public Law 110-326, with the Identity Theft Enforcement and Restitution Act | Law | Cross-sector | Confirmed | [63] |
| 2008-10 | ATT&CK: Conficker first detected | Malware | Cross-sector | Reported | [20] |
| 2008-10 | CCDCOE accredited as a NATO International Military Organization | Policy | Defense | Confirmed | [67] |
| 2008-10-01 | PCI DSS v1.2 generally available; v1.1 sunsets 31 Dec | Standards | Payments | Confirmed | [13] |
| 2008-10-02 | Walker and Gembe indicted in Los Angeles over DDoS on two US satellite retailers. Home: [Four Books on Cybercrime](/case-studies/CYBERCRIME_FOUR_BOOKS.md); Chromium blog's Chrome sandbox post | Crime; Platform | Retail; technology | Confirmed | [14][72] |
| 2008-10-07 | Adobe APSA08-08: Flash Player workaround for clickjacking | Vulnerability | Cross-sector | Confirmed | [73] |
| 2008-10-08 | Indictment in the governor's e-mail case announced (returned 7 Oct, E.D. Tenn.) | Crime | Government (personal account) | Confirmed (as alleged) | [53] |
| 2008-10-14 | Microsoft's October bulletin summary carries an Exploitability Index | Defender tooling | Technology | Confirmed (presence); Inferred (first appearance) | [74] |
| 2008-10-20 | FBI announces the end of its two-year DarkMarket undercover operation: 56 arrests. Home: [Four Books on Cybercrime](/case-studies/CYBERCRIME_FOUR_BOOKS.md) | Crime | Financial | Confirmed | [15] |
| 2008-10-23 | MS08-067 out of band (CVE-2008-4250); CERT/CC VU#827267 reports exploitation; NVD records Gimmiv.A | Vulnerability | Cross-sector | Confirmed | [16][17][18] |
| 2008-11 | ATT&CK: some Stuxnet components in use. Home: [Stuxnet](/case-studies/STUXNET.md) | State | Industrial | Confirmed | [41] |
| 2008-11-04 | CERT/CC VU#593409: Adobe Reader and Acrobat util.printf() overflow (CVE-2008-2992) | Vulnerability | Cross-sector | Confirmed | [22] |
| 2008-11-25 | CWE news says the SANS/MITRE Top 25 is scheduled for 10 Dec | Standards | Cross-sector | Confirmed (schedule only) | [59] |
| 2008-11-30 | ThreatExpert analyses Agent.btz and ties it to the Central Command breach reported in the press | State | Defense | Reported | [32] |
| 2008-12 | Kaspersky first blocks Fanny | State | Unknown | Confirmed (vendor's analysis) | [39] |
| 2008-12-08 | CSIS commission report; Council Directive 2008/114/EC on European critical infrastructures | Policy | Government; critical infrastructure | Confirmed | [64][65] |
| 2008-12-09 | Internet Explorer data binding flaw public (VU#493881, published 11 Dec; NVD CVE-2008-4844 on 11 Dec) | Vulnerability | Cross-sector | Confirmed | [25][27] |
| 2008-12-17 | MS08-078 out of band; US-CERT's alert (archived by CISA) says the flaw is being actively exploited | Vulnerability | Cross-sector | Confirmed | [26][25] |
| 2008-12-30 | MD5 rogue CA research at 25C3; Microsoft Advisory 961509; VU#836068 (published 31 Dec) | Research | PKI, cross-sector | Confirmed | [28][30][31] |
| 2008-12-31 (boundary) | PCI DSS v1.1 sunsets | Standards | Payments | Confirmed | [13] |
| 2009-01-20 (boundary) | Heartland discloses a 2008 breach within its processing system. Home: [E-Commerce Threats](/case-studies/ECOMMERCE_THREATS.md) | Card theft | Payments | Confirmed | [12] |
| 2009-03 (boundary) | Cambridge technical report on the OHHDL compromise | State | Government (exile), NGO | Confirmed | [35] |
| 2009-03-28 (boundary) | Information Warfare Monitor publishes "Tracking GhostNet" | State | Government, NGO | Confirmed | [36] |
| 2010 (boundary) | Lynn's Foreign Affairs article on the 2008 breach; CCDCOE's legal analysis of 2008 incidents | State | Defense | Confirmed | [23][38] |
| 2011-10-20 (boundary) | First Circuit decides Anderson v. Hannaford | Law | Retail (grocery) | Confirmed | [56] |
| 2014-03-12 to 2017-04-11 (boundary) | Kaspersky's Agent.btz (2014), Regin (2014), Equation (2015) and Lamberts (2017) reports | State | Various | Confirmed | [33][42][39][43] |
| 2015-08-24 (boundary) | Third Circuit decides FTC v. Wyndham | Law | Hospitality | Confirmed | [57] |
| 2022-03-03 to 2026-07-13 (boundary) | Six CVE-2008 ids added to KEV | Vulnerability | Cross-sector | Confirmed | [19] |

## Part 2: the vulnerability record

### Debian's predictable random numbers

On 13 May Debian published DSA-1571-1: a Debian-specific change to OpenSSL had made its random number generator predictable from version 0.9.8c-1 onward (Confirmed [5]). Debian listed SSH, OpenVPN, DNSSEC and X.509/TLS keys as affected, said all DSA keys used on affected systems should be considered compromised, and told users to upgrade and then regenerate all key material (Confirmed [5]). CERT/CC's VU#925211, public on 13 May and published on 15 May, covers Debian and Ubuntu packages and says keys generated on or after 17 September 2006 may be weak (Confirmed [3]). NVD published CVE-2008-0166 on 13 May, lists OpenSSL 0.9.8c-1 up to before 0.9.8g-9 on Debian-based systems, and classifies it CWE-338, Use of Cryptographically Weak Pseudo-Random Number Generator (Confirmed [4]). Debian's security tracker lists DSA-1571-1 as "openssl - predictable random number generator", citing CVE-2008-0166 (Confirmed [6]).

The lesson is in Debian's instruction, not the patch. A fixed library stops new weak keys but does nothing for the keys already made, so the remedy was key rotation across every service that had generated keys on an affected system (Inferred from [5]).

### The SQL injection wave

Microsoft Security Advisory 954462, published on 24 June, is titled "Rise in SQL Injection Attacks Exploiting Unverified User Data Input" (Confirmed [7]). It describes an escalating wave of automated SQL injection against ASP and ASP.NET sites that do not validate input, and says it was not a vulnerability in any Microsoft product (Confirmed [7]). Compromised servers could forward visitors to sites that installed malware (Confirmed [7]). Microsoft pointed site owners to three tools: HP Scrawlr to detect the flaw, UrlScan 3.0 Beta to filter requests and the Microsoft Source Code Analyzer for SQL Injection to find it in code (Confirmed [7]).

Because no vendor product was at fault, the wave has no CVE id and is easy to miss in a history built from CVE records (Inferred). In ATT&CK terms the first step reads as T1190 Exploit Public-Facing Application and the visitor-facing result as T1189 Drive-by Compromise; that is this study's later mapping, as no 2008 record carries ATT&CK ids (Inferred [7]).

### DNS cache poisoning

On 8 July CERT/CC published VU#800113, "Multiple DNS implementations vulnerable to cache poisoning", covering CVE-2008-1447: weaknesses in the DNS protocol and in common implementations let forged records be inserted into caching resolvers (Confirmed [8]). The note traces the weakness to weak transaction-ID randomness and fixed or predictable source ports (Confirmed [8]). Its mitigations were per-query source port randomization, which makes the attack less practical but is not a full fix, patching stub resolvers, restricting recursion, filtering spoofed traffic under RFC 2827 and RFC 3704, and checking NAT and PAT devices, which can reduce source port randomness (Confirmed [8]). Vendors named DNSSEC as the only full solution, and patches followed from July to September 2008 (Confirmed [8]).

Microsoft's MS08-037, also published on 8 July and rated Important, fixed CVE-2008-1447 (DNS Insufficient Socket Entropy) and CVE-2008-1454 (DNS Cache Poisoning) in Windows 2000, XP, Server 2003 and Server 2008 (Confirmed [9]). NVD lists BIND 8 and 9 before 9.5.0-P1, 9.4.2-P1 and 9.3.5-P1, Microsoft DNS and other implementations as affected, classifies the flaw CWE-331, Insufficient Entropy, and shows no KEV date; it is not in the KEV catalog (Confirmed [10][19]). CAPEC-142 DNS Cache Poisoning is the attack pattern; no ATT&CK technique describes resolver cache poisoning cleanly, so this study binds none (Confirmed [75]; Inferred).

The policy answer came within weeks. OMB memorandum M-08-23 required DNSSEC on the top-level .gov domain by January 2009 and on all federal information systems by December 2009, with draft agency plans due on 5 September 2008 (Confirmed [70]).

### MS08-067 and Conficker

Microsoft published MS08-067, "Vulnerability in Server Service Could Allow Remote Code Execution (958644)", on 23 October, outside the monthly cycle (Confirmed [16][74]). The flaw, CVE-2008-4250, allowed unauthenticated remote code execution through the Server service's RPC handling on Windows 2000, XP and Server 2003, where it was rated Critical; it was rated Important on Vista and Server 2008 (Confirmed [16]). Microsoft said it "could be used in the crafting of a wormable exploit" and that it was aware of limited, targeted attacks; its workarounds were to block TCP ports 139 and 445 at the firewall and to disable the Server and Computer Browser services (Confirmed [16]). CERT/CC's VU#827267, public the same day, said exploit code was publicly available and the flaw was "being currently exploited in the wild" (Confirmed [17]). NVD published CVE-2008-4250 on 23 October, records exploitation in the wild by Gimmiv.A in October 2008, and lists CWE-94 and CWE-119 (Confirmed [18]). CISA added it to KEV on 20 May 2026 as "Microsoft Windows Buffer Overflow Vulnerability" (Confirmed [19]).

ATT&CK's software entry S0608 Conficker, aliases Kido and Downadup, describes a worm first detected in October 2008 that spread through MS08-067 (Reported [20]). The detection month is ATT&CK's summary from secondary sources; other accounts of the start month were not checked (Reported [20]). ATT&CK lists 13 Enterprise techniques for the worm, and the library's page carries the same 13: T1547.001, T1543.003, T1685, T1568.002, T1210, T1105, T1490, T1112, T1046, T1027, T1021.002, T1091 and T1124, plus three ICS techniques, T0826, T0828 and T0847 (Confirmed [20]; Demonstrated [76]). Microsoft's KB 962007 says Conficker spreads through the MS08-067 flaw, through network shares and through AutoPlay, and lists symptoms including tripped account lockout policies and disabled Automatic Updates, Background Intelligent Transfer Service, Windows Defender and Error Reporting services (Confirmed [21]). Most of the worm's mass spread belongs to 2009, so this chronicle records only its start (Inferred).

The same flaw is part of Stuxnet's story; the [Stuxnet](/case-studies/STUXNET.md) study is its home and records MS08-067 among the flaws Stuxnet used (Confirmed [78]).

### Documents and the browser

CERT/CC's VU#593409, public on 4 November, covers a stack buffer overflow in the util.printf() JavaScript function of Adobe Reader and Acrobat, CVE-2008-2992; NVD lists CWE-787 and CISA added it to KEV on 3 March 2022 (Confirmed [22][19]). A second Adobe Reader and Acrobat flaw, CVE-2008-0655, published by NVD on 7 February, was added to KEV on 8 June 2022 (Confirmed [19]).

The year's last client-side emergency was Internet Explorer's data binding flaw. US-CERT's VU#493881 was public on 9 December and published on 11 December, and NVD published CVE-2008-4844 on 11 December as a use-after-free in mshtml.dll data binding, classified CWE-399 (Confirmed [25][27]). On 17 December US-CERT's alert (now archived on CISA's site) said exploit code was public and the flaw "is being actively exploited", and Microsoft issued MS08-078 out of band, rated Critical, for Internet Explorer 5.01 SP4 through Internet Explorer 7 and Internet Explorer 8 Beta 2 (Confirmed [25][26]). Microsoft said at release that it had information the flaw was being exploited and that it had been publicly disclosed (Confirmed [26]).

Adobe's APSA08-08 of 7 October, "Flash Player workaround available for Clickjacking issue", rated the issue critical for Flash Player 9.0.124.0 and earlier; the fix was Flash Player 10.0.12.36 or 9.0.151.0 under APSB08-18 (Confirmed [73]). Clickjacking as a class has no single CVE; CAPEC-103 Clickjacking and CWE-1021 are this study's pairings (Inferred [73]).

### The MD5 rogue certificate authority

On 30 December Alexander Sotirov, Marc Stevens, Jacob Appelbaum, Arjen Lenstra, David Molnar, Dag Arne Osvik and Benne de Weger presented "MD5 considered harmful today" at 25C3: a practical MD5 chosen-prefix collision against a commercial CA that still signed with MD5 yielded a rogue CA certificate trusted by common browsers (Confirmed [28][29]). They backdated the certificate so it had already expired, and recommended that CAs drop MD5, randomize serial numbers and use path-length constraints, and that browsers warn on MD5 certificates (Confirmed [29]). Microsoft's Advisory 961509 the same day said this was not a vulnerability in a Microsoft product, that it knew of no active attacks, that CAs should stop signing with MD5, that EV certificates had always been signed with SHA-1, and that its Security Development Lifecycle already barred MD5 as a default (Confirmed [30]). CERT/CC's VU#836068, "MD5 vulnerable to collision attacks", was public on 30 December and published on 31 December with no CVE (Confirmed [31]). The library has a page for CAPEC-459, Creating a Rogue Certification Authority Certificate (Confirmed [31][75]).

### The KEV tail

CISA's KEV catalog, version 2026.11.10, lists six CVE-2008 ids (Confirmed [19]):

| CVE | Product and flaw | NVD published | KEV dateAdded | Sources |
|---|---|---|---|---|
| CVE-2008-2992 | Adobe Acrobat and Reader, util.printf() overflow (CWE-787) | 2008-11-04 | 2022-03-03 | [19][22] |
| CVE-2008-3431 | Sun xVM VirtualBox | 2008-08-05 | 2022-03-03 | [19] |
| CVE-2008-0655 | Adobe Acrobat and Reader | 2008-02-07 | 2022-06-08 | [19] |
| CVE-2008-0015 | Microsoft Windows Video ActiveX Control, remote code execution (KEV's name) | not checked | 2026-02-17 | [19] |
| CVE-2008-4250 | Windows Server service, MS08-067 (CWE-94, CWE-119) | 2008-10-23 | 2026-05-20 | [18][19] |
| CVE-2008-4128 | Cisco IOS HTTP administration, cross-site request forgery (CWE-352) | 2008-09-18 | 2026-07-13 | [19] |

The gap between event and listing runs from 14 to 18 years, so KEV dates say when CISA had evidence of exploitation, not when the exploitation happened (Inferred [19]).

## Part 3: card theft and the crime record

### Hannaford (new to the library)

The library's [E-Commerce Threats](/case-studies/ECOMMERCE_THREATS.md) study names Hannaford only among the records it could not open, so this chronicle carries the court record (Confirmed [78]). The First Circuit's opinion in Anderson v. Hannaford Bros. Co., decided on 20 October 2011, recites the plaintiffs' allegations: hackers breached Hannaford's electronic payment processing system as early as 7 December 2007 and stole up to 4.2 million card numbers, expiration dates and security codes (Confirmed [56]). Visa notified Hannaford on 27 February 2008; Hannaford found the means of access on 8 March, contained the breach on 10 March and announced it on 17 March, by which time more than 270 stores were involved and about 1,800 fraud cases had been reported (Confirmed [56]). The court held that reasonably foreseeable mitigation costs are cognizable under Maine law (Confirmed [56]). The opinion as read here describes no intrusion method, so this study binds no ATT&CK technique to Hannaford (Inferred).

### TJX, the Gonzalez ring and Dave & Buster's (summary)

The [E-Commerce Threats](/case-studies/ECOMMERCE_THREATS.md) study, Part 2.2, is the home for TJX and the Gonzalez ring (Confirmed [78]). The 2008 record has four dated pieces. On 27 March the FTC announced a proposed consent order with TJX, in a release that also announced separate actions against the data brokers Reed Elsevier and Seisint for failing to provide adequate security for consumers' data; the final Decision and Order followed on 1 August (Confirmed [58]). On 12 May the Justice Department unsealed an Eastern District of New York indictment, returned on 12 March, charging two foreign nationals, and a complaint charging Albert Gonzalez, over intrusions into cash register terminals at 11 Dave & Buster's restaurants to take track 2 card data (Confirmed [49]); a packet sniffer was placed on the register terminals (Confirmed [51]). On 5 August a Boston grand jury indictment charged eleven defendants, including Gonzalez under the name "Segvec", over the hacking of nine major US retailers, among them TJX, BJ's Wholesale Club, OfficeMax, Boston Market, Barnes & Noble, Sports Authority, Forever 21 and DSW, and the theft and sale of more than 40 million card numbers (Confirmed [51]). DOJ alleged that the ring got in by wardriving into retailers' wireless networks, installed sniffer programs that captured card numbers, passwords and account data, held the data on encrypted servers in Eastern Europe and the United States, and cashed out with blank cards at ATMs; it said Gonzalez had been a Secret Service confidential informant after a 2003 arrest, and called the case the largest hacking and identity theft case it had prosecuted (Confirmed [51]).

### Heartland (summary)

Heartland's home is Part 2.3 of [E-Commerce Threats](/case-studies/ECOMMERCE_THREATS.md) (Confirmed [78]). Its Form 8-K of 20 January 2009 says it "was the victim of a security breach within its processing system in 2008" (Confirmed [12]). Visa and MasterCard had alerted it to suspicious activity, forensic auditors found malicious software that compromised data crossing its network, and the evidence was found the week before the disclosure (Confirmed [12]). Heartland said the breach might be part of a widespread global cyber fraud operation, that it was cooperating with the Secret Service and the Justice Department, and that no Social Security numbers or unencrypted PINs were involved (Confirmed [12]).

### Wyndham's first intrusion (summary)

Wyndham's home is Part 2.4 of [E-Commerce Threats](/case-studies/ECOMMERCE_THREATS.md) (Confirmed [78]). The Third Circuit's 2015 opinion in FTC v. Wyndham recites the FTC's allegations: in April 2008 hackers broke into the network of a Phoenix hotel that was connected to Wyndham's network, brute-forced an administrator account on Wyndham's network, and sent unencrypted information for more than 500,000 accounts to a domain in Russia (Confirmed [57]). Further intrusions followed in March 2009 and late 2009, and in all more than 619,000 consumers were affected with at least $10.6 million in fraudulent charges (Confirmed [57]).

### The payment networks as sensor

Visa told Hannaford, and Visa and MasterCard told Heartland (Confirmed [56][12]). In both cases the first sign of the breach came from outside the company, from the fraud patterns the card brands saw (Inferred [56][12]).

### Prosecutions and takedowns

- **Spam and stock fraud.** On 3 January a 41-count indictment was unsealed in Detroit charging Alan Ralsky and ten others in an international illegal spamming and stock fraud scheme (Confirmed [48]).
- **The US and Romania.** On 19 May US and Romanian officials announced, in Bucharest, charges against 38 individuals in two related computer and card fraud cases: 33 in a 65-count racketeering indictment in Los Angeles and seven in a Connecticut phishing indictment (Confirmed [50]).
- **A botnet for sale.** On 21 August a Brazilian national was charged in the Eastern District of Louisiana with conspiring to sell a botnet; the indictment alleges more than 100,000 computers were damaged (Confirmed [52]).
- **A DDoS-for-hire case.** On 2 October Lee Graham Walker of England and Axel Gembe of Germany were indicted in Los Angeles for conspiring to DDoS the websites of two US satellite retailers, in the Echouafni and Ashley conspiracy (Confirmed [14]). The home study is [Four Books on Cybercrime](/case-studies/CYBERCRIME_FOUR_BOOKS.md) (Confirmed [78]).
- **A personal e-mail account.** On 8 October the Justice Department announced the indictment, returned on 7 October in the Eastern District of Tennessee, of a 20-year-old charged with gaining access on about 16 September to Governor Sarah Palin's personal e-mail account by resetting the password through its security questions, then posting screenshots publicly (Confirmed [53]).
- **DarkMarket.** On 20 October the FBI said it had wrapped up, the week before, a two-year undercover operation against the DarkMarket carding forum, which had more than 2,500 registered members at its peak; an FBI agent using the name "Master Splyntr" served as a site administrator, and the operation produced 56 arrests worldwide and prevented an estimated $70 million in losses (Confirmed [15]). The [Four Books on Cybercrime](/case-studies/CYBERCRIME_FOUR_BOOKS.md) study tells the forum's story from the books' side (Confirmed [78]).
- **McKinnon.** On 30 July the House of Lords dismissed Gary McKinnon's appeal against extradition; the US request alleged unauthorized access to 97 US Government computers between 1 February 2001 and 19 March 2002 (Confirmed [54]).
- **Researchers and a court order.** EFF's case page for MBTA v. Anderson says a federal court in Massachusetts issued a temporary restraining order on 9 August that stopped three MIT students' DEF CON talk on fare-system weaknesses under a computer fraud claim, that it was lifted on 19 August, and that the MBTA and the students announced cooperation on 22 December (Reported, EFF as counsel [55]).

### What law changed

Public Law 110-326, approved on 26 September, contains in Title II the Identity Theft Enforcement and Restitution Act of 2008 (Confirmed [63]). It lets courts order restitution for the value of victims' time spent remediating identity theft, and amends 18 USC 1030 on damage definitions, cyber-extortion in (a)(7), conspiracy in (b) and full interstate and foreign commerce reach in (e)(2)(B) (Confirmed [63]).

## Part 4: the state record

### Buckshot Yankee and Agent.btz

The official account opened for this study is William J. Lynn III's, written as Deputy Secretary of Defense in Foreign Affairs in September/October 2010 (Confirmed [23]). In 2008, he wrote, an infected flash drive was inserted into a US military laptop at a base in the Middle East; code "placed there by a foreign intelligence agency" uploaded itself onto a network run by US Central Command and spread on classified and unclassified systems (Confirmed [23]). He called it the most significant breach of US military computers ever, named the Pentagon's counter-operation Operation Buckshot Yankee, called it a turning point in US cyberdefense strategy, and named the new US Cyber Command (Confirmed [23]). Lynn names neither the country nor the malware (Confirmed [23]).

The malware name comes from elsewhere. ThreatExpert's post of 30 November 2008 analysed Agent.btz, which spreads by dropping a copy of itself and an autorun file on newly connected removable drives, and tied it to the breach that senior military leaders had reported on the Central Command network, relying on a press report for that link (Reported [32]). ATT&CK's S0092 Agent.btz, version 1.1, describes a worm that spreads mainly through removable devices such as USB drives and "reportedly infected U.S. military networks in 2008"; it lists no associated group and six techniques, T1091, T1052.001, T1560.003, T1105, T1016 and T1033, citing Shevchenko (30 November 2008) and Gostev (12 March 2014) (Confirmed [24]). Kaspersky's Gostev wrote in 2014 that the worm became public in late 2008 after the military infection and dates its origins to 2007; Turla shares log-file names and an XOR key with it, but Gostev says that is not enough to conclude a common origin, as the key had been public since 2008, and Red October's USB stealer searched for Agent.btz files (Confirmed [33]). ATT&CK's G0010 Turla, attributed to Russia's FSB, does not mention the 2008 incident and does not list S0092 among its software (Confirmed [34]). This study therefore links Agent.btz to Buckshot Yankee only as an inference and does not bind the 2008 breach to Turla (Inferred).

### The Dalai Lama's office and GhostNet

In September 2008 Shishir Nagaraja travelled to Dharamsala to help a forensic investigation of the Office of His Holiness the Dalai Lama (Confirmed [35]). The Cambridge technical report he wrote with Ross Anderson, UCAM-CL-TR-746 (March 2009), describes e-mail lures written to look as if they came from fellow Tibetans and co-workers, carrying malicious attachments, and mail stolen in transit with its attachments replaced by malicious ones; F-Secure found the samples supported file search and retrieval and keylogging (Confirmed [35]). The report's abstract speaks of "agents of a nation state" and "a major power", its conclusion says agents of the Chinese government compromised the office, and it notes that a capable, motivated individual could have mounted the attack (Confirmed [35]).

The Information Warfare Monitor's "Tracking GhostNet", published on 28 March 2009 after a ten-month investigation, found more than 1,295 infected hosts in 103 countries, close to 30% of them high-value targets; it says the evidence "circumstantially" points to China but that the researchers do not know the attackers' identity or motive (Confirmed [36]). The summary page names no malware and gives no calendar dates (Confirmed [36]). ATT&CK's S0032 gh0st RAT is a public-source tool used by many groups and does not mention GhostNet, Tibet or 2008, so this study binds GhostNet to no software or group (Confirmed [37]).

### Georgia, August 2008

CCDCOE's "International Cyber Incidents: Legal Considerations" (Tikk, Kaska and Vihul, 2010) dates the cyber attacks on Georgia from 8 to 28 August 2008, during the armed conflict over South Ossetia (Confirmed [38]). It lists the methods as denial of service and DDoS, a distributed batch-script attack tool with instructions, an exploited SQL vulnerability, defacement, and spam and targeted e-mail, and the targets as the President, Parliament, ministries, news and media, forums and financial institutions (Confirmed [38]). Shadowserver logged the first incidents on 8 August; the President's site was defaced with images likening Saakashvili to Hitler and was under sustained DDoS as of 11 August (Confirmed [38]). Poland's President hosted Georgian press releases, Estonia hosted the foreign ministry site and sent two CERT-EE specialists, and Georgia's academic CERT coordinated mitigation, blocked Russian websites and moved services abroad (Confirmed [38]).

The attribution record has four layers. CCDCOE's own finding is that organised Russian hacker groups were most likely behind the exploit attacks, that there was "no evident link to the Russian administration or state organisations guiding or directing attacks", that Russia denied involvement, and that there was "no conclusive proof" of who ran the DDoS or the defacements (Confirmed [38]). Georgia's foreign ministry said on 11 August that "a cyber warfare campaign by Russia" was disrupting its websites, posting through a replacement blog; CCDCOE quotes it and this study did not open the original (Reported [38]). Project Grey Goose's Jeff Carr concluded that Russian hackers were "primed for the assault" by government or military officials, citing a target site that was live within hours with vetted target lists, and SecureWorks' Don Jackson pointed to the timing and to command servers in address ranges of Russian state-operated companies (Reported, both as quoted by CCDCOE [38]). Network World's 2010 review of Joseph Menn's Fatal System Error says the book describes Russian Business Network services being used in DoS attacks, data theft and defacements against Georgian government networks; this study does not adopt that attribution (Reported [11]). NATO's own page says only that the conflict "demonstrated that cyber attacks have the potential to become a major component of conventional warfare" (Confirmed [66]).

The [Sandworm operations](/case-studies/SANDWORM_OPERATIONS.md) study covers the 2019 attack on Georgia, which governments did attribute; it is a different event (Confirmed [78]).

### Belarus and Lithuania, the same pattern earlier

From 8 AM on 26 April to the evening of 28 April, the RFE/RL Belarus service, seven other RFE/RL sites and independent Belarusian news sites were flooded at about 50,000 fake pings a second during coverage of a Chernobyl-anniversary rally (Confirmed [38]). RFE/RL and public opinion leaned towards Belarusian government backing, but CCDCOE says traffic data gave no evidence of a government agent, Belarus denied involvement, and the origin is undetermined (Confirmed [38]).

From 28 June to 2 July, after Lithuania banned Soviet insignia, more than 300 websites, 95% private and 5% government, were defaced with pro-Soviet symbols and slogans; almost all sat on one hosting provider's vulnerable server, CERT-LT had warned in advance, and the origin is undetermined (Confirmed [38]).

### Operations the world learned of later

- **Fanny.** Kaspersky's 2015 Equation report says the Fanny worm was presumably compiled in July 2008 (timestamp 28 July) and first blocked in December 2008; it used two zero-days later seen in Stuxnet, the LNK exploit and the flaw fixed in MS09-025, spread by USB and mapped air-gapped networks over a USB-based command channel; a GrayFish installer was compiled on 1 February 2008 (Confirmed [39]). ATT&CK's G0020 Equation gives no sponsor and no dates, lists T1480.001, T1564.005, T1120 and T1542.002, and lists no software; Fanny is not an ATT&CK object (Confirmed [40]). Home: [United States-attributed threat actors](/case-studies/THREAT_ACTORS_UNITED_STATES.md); the [Stuxnet](/case-studies/STUXNET.md) study covers the LNK flaw it shared.
- **Stuxnet.** ATT&CK's S0603 says Stuxnet was "discovered in 2010, with some components being used as early as November 2008", with no associated group (version 1.5, modified 24 April 2026) (Confirmed [41]). Home: [Stuxnet](/case-studies/STUXNET.md).
- **Regin.** Kaspersky's 2014 report decodes a GSM base station controller log covering about 25 April to 27 May 2008, with commands on 136 cells; it counts 27 victims in 14 countries, calls nation-state support likely, warns that metadata may be a false flag and names no country (Confirmed [42]). ATT&CK's S0019 Regin has a library page (Confirmed [42]; Demonstrated [76]). Homes: [United States-attributed threat actors](/case-studies/THREAT_ACTORS_UNITED_STATES.md) and [The Hacker and the State](/case-studies/HACKER_AND_THE_STATE_CASES.md).
- **The Lamberts.** Kaspersky wrote in 2017 that "since at least 2008, The Lamberts have used multiple sophisticated attack tools", named no actor or country, and noted that Symantec calls the actor Longhorn (Confirmed [43]). ATT&CK's S0690 Green Lambert has a library page (Confirmed [43]; Demonstrated [76]). Home: [United States-attributed threat actors](/case-studies/THREAT_ACTORS_UNITED_STATES.md).

### Groups ATT&CK dates to 2008

Four ATT&CK groups in the library's data are described as active since at least 2008, and none of their entries names a dated 2008 operation (Confirmed [44][45][46]; Demonstrated [76]). G0016 APT29, attributed to Russia's SVR, "operated since at least 2008" against European and NATO government networks, research institutes and think tanks (Confirmed [44]). G0001 Axiom is a suspected Chinese espionage group targeting aerospace, defense, government, manufacturing and media since at least 2008 (Confirmed [45]). G0060 BRONZE BUTLER, with likely Chinese origins, has been active since at least 2008, mainly against Japanese government, biotechnology, electronics manufacturing and industrial chemistry organizations (Confirmed [46]). G0053 FIN5, a financially motivated group whose members likely speak Russian, has been active since at least 2008 against the restaurant, gaming and hotel industries' payment card and personal data; nothing in its entry ties it to the Gonzalez ring, Hannaford, Heartland or Wyndham (Demonstrated [76]). G0007 APT28, GRU unit 26165, and G0010 Turla, the FSB, were active across 2008 by ATT&CK's dates, which start in 2004, but ATT&CK names no 2008 operation for either (Confirmed [47][34]). The [Russia-attributed](/case-studies/THREAT_ACTORS_RUSSIA.md) and [China-attributed](/case-studies/THREAT_ACTORS_CHINA.md) threat actor studies are the homes for the state groups (Confirmed [78]).

## Part 5: internet infrastructure and industrial systems

### The YouTube prefix hijack

RIPE NCC's case study records that at 18:47 UTC on Sunday 24 February 2008 Pakistan Telecom (AS17557) began an unauthorised announcement of 208.65.153.0/24, part of YouTube's address space (Confirmed [2]). PCCW Global (AS3491) propagated it and YouTube's traffic worldwide was redirected to Pakistan (Confirmed [2]). YouTube announced the /24 at 20:07 and two more-specific /25 prefixes at 20:18, and PCCW withdrew the prefixes at 21:01 UTC (Confirmed [2]). It was a routing incident, not an intrusion, with no CVE and no ATT&CK technique that fits (Confirmed [2]; Inferred for the mapping).

### The grid and nuclear plants

FERC Order No. 706 (Docket RM06-22-000, 73 FR 7368), published on 7 February and effective on 7 April, approved eight NERC Critical Infrastructure Protection Reliability Standards that require users, owners and operators of the Bulk-Power System to safeguard critical cyber assets, and directed NERC to modify them (Confirmed [60]). A FERC proposed rule of 25 September (73 FR 55459) proposed that facilities in US nuclear plants not regulated by the NRC are subject to the same eight standards (Confirmed [61]).

NIST SP 800-82 Rev. 3 lists a 2008 incident at the Hatch nuclear plant in the US state of Georgia: a software update on a single Windows computer reset control-system data on reboot, safety systems read the missing data as a drop in cooling water reservoirs, and the plant went into a 48-hour emergency shutdown (Reported [62]). NIST footnotes a news site, not a regulator record, and the event was not an attack (Reported [62]). No ATT&CK for ICS technique is bound to it (Inferred).

### Europe's critical infrastructure

Council Directive 2008/114/EC of 8 December 2008 covers the identification and designation of European critical infrastructures and the assessment of the need to improve their protection; Annex I lists the sectors and Annex II sets the operator security plan procedure (Confirmed [65]). The sector list itself was not read (not checked).

## Part 6: law, policy, standards and the defender view

### US policy

The national cybersecurity initiative known as CNCI was launched by President George W. Bush in NSPD-54/HSPD-23 in January 2008 (Confirmed [1]). The archived White House page lists Trusted Internet Connections, consolidating external access points, as initiative 1; EINSTEIN 2, signature-based intrusion detection sensors on federal internet traffic reporting to US-CERT, as initiative 2; EINSTEIN 3, intrusion prevention planned with NSA-developed technology, as initiative 3; connected cyber operations centers; a government-wide cyber counterintelligence plan; and classified-network security (Confirmed [1]). The CSIS Commission on Cybersecurity for the 44th Presidency published its final report on 8 December; its three findings were that cybersecurity is a major national security problem, that action must respect privacy and civil liberties, and that only a national strategy covering both domestic and international aspects will improve the situation (Confirmed [64]).

### NATO and CCDCOE

NATO's cyber defence page says that after the 2007 attacks on Estonia the Alliance approved its first Policy on Cyber Defence in January 2008 (Confirmed [66]). CCDCOE was established on 14 May 2008 on the initiative of Estonia with Germany, Italy, Latvia, Lithuania, the Slovak Republic and Spain, and the North Atlantic Council granted it full accreditation and International Military Organization status in October 2008 (Confirmed [67]). Its later legal analysis is the main source for this study's Georgia, Belarus and Lithuania sections (Confirmed [38]).

### Payment standards

The PCI Security Standards Council made PCI DSS version 1.2 generally available on 1 October 2008, effective immediately, with version 1.1 sunsetting on 31 December 2008 (Confirmed [13]). The release added no new major requirements to the existing 12 and set a June 2010 sunset for WEP wireless implementations (Confirmed [13]). The [E-Commerce Threats](/case-studies/ECOMMERCE_THREATS.md) study carries the PCI DSS history (Confirmed [78]).

### The vocabulary of weaknesses

MITRE's CWE news archive records three 2008 firsts: NVD began using CWE mappings (item of 12 March), a Core Security advisory became the first advisory to include a CWE id (advisory of 25 March, CWE news item of 26 March), and CWE version 1.0 was posted on 9 September, followed by 1.0.1 on 14 October and 1.1 on 25 November (Confirmed [59]). The item of 25 November said the SANS/MITRE Top 25 Most Dangerous Programming Errors was scheduled for initial release on 10 December; the actual release date was not checked (Confirmed [59]).

### Guides, protocols and platforms

- **Incident handling.** NIST published SP 800-61 Rev. 1, Computer Security Incident Handling Guide, in March 2008; it was withdrawn on 6 August 2012 and superseded by Rev. 2 (Confirmed [68]).
- **Testing.** NIST published SP 800-115, Technical Guide to Information Security Testing and Assessment, in September 2008 (Confirmed [71]).
- **TLS 1.2.** RFC 5246 was published in August 2008 as a Proposed Standard; it obsoletes RFCs 3268, 4346 and 4366 and was later obsoleted by RFC 8446 (Confirmed [69]).
- **Browser sandboxing.** The Chromium blog published "A new approach to browser security: the Google Chrome Sandbox" on 2 October 2008; only the title and date were readable (Confirmed [72]).
- **Exploitability ratings.** Microsoft's October 2008 bulletin summary has an Exploitability Index section and the September summary does not; that the index first appeared in October is this study's reading (Confirmed [74]; Inferred).

### The defender view

**The patch was not the end.** Debian's fix had to be followed by key regeneration, and US-CERT said DNS port randomization reduced, but did not remove, the risk (Confirmed [5][8]). The [vulnerability management reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md) covers verifying remediation (Inferred).

**Out-of-band was the signal.** MS08-067 and MS08-078 both shipped outside the monthly cycle, both with exploitation already known (Confirmed [16][17][26][25]). An organization that patched only on the monthly cycle would have been exposed for weeks (Inferred).

**Removable media crossed air gaps.** Agent.btz, Fanny and Conficker all moved on removable drives in the record, and Fanny mapped air-gapped networks over a USB channel (Confirmed [21][39]; Reported [24]).

**Detection came from outside.** The payment networks detected Hannaford and Heartland, and the 2008 military breach is known from an official article published two years later (Confirmed [56][12][23]; Inferred for the pattern).

**Federal sensors were being built.** EINSTEIN 2's signature-based detection and Trusted Internet Connections were CNCI's first two initiatives (Confirmed [1]). The [incident response reference](/INCIDENT_RESPONSE_REFERENCE.md) covers detection programs (Inferred).

## Part 7: MITRE mappings

No 2008 record opened here carries an ATT&CK id; ATT&CK did not exist (Inferred). CWE reached version 1.0 in September (Confirmed [59]). Every Enterprise binding below is either a technique ATT&CK lists for an object it dates to 2008 (S0608 Conficker, S0092 Agent.btz) or this study's later mapping of a behavior a primary source describes (Inferred). Every id was checked against the library's data files (`data/attack/technique_profiles.jsonl`, `software_to_technique.jsonl`, `groups.jsonl`, `software.jsonl`, `campaigns.jsonl`, `technique_to_d3fend.jsonl`, `data/attack/ics/` and `data/weaknesses/`) and against the generated pages under `mitre/` (Demonstrated [75][76]). Names and tactics are those of ATT&CK v20.0 as the library carries them, including the v20.0 tactics stealth and defense-impairment (Demonstrated [76]).

The Basis column says how strong each tie is, as in the [2016 chronicle](/case-studies/CHRONICLE_2016.md). **Listed** means ATT&CK itself lists the id for the object. **Described** means a primary source describes the behavior and this study assigns the id. **Reported** means only a secondary source supports the behavior. **Inferred** means no source describes the behavior in enough detail and the mapping rests on this study's reading.

### ATT&CK Enterprise techniques

| Id | Name (ATT&CK v20.0) | Tactic(s) | Basis | Dated event or report | Sources |
|---|---|---|---|---|---|
| [`T1210`](/mitre/techniques/T1210.md) | Exploitation of Remote Services | lateral-movement | Listed (S0608); Described | Conficker through MS08-067 (Oct, ATT&CK); MS08-067 exploited in the wild by Gimmiv.A (Oct) and per CERT/CC (23 Oct) | [20][18][17][16] |
| [`T1091`](/mitre/techniques/T1091.md) | Replication Through Removable Media | lateral-movement, initial-access | Listed (S0608, S0092); Described | Lynn's infected flash drive (2008); Agent.btz (2008, reportedly); Conficker AutoPlay (KB 962007); Fanny's USB spread (compiled Jul) | [23][24][32][21][20][39] |
| [`T1021.002`](/mitre/techniques/T1021-002.md) | SMB/Windows Admin Shares | lateral-movement | Listed (S0608); Described | Conficker spread through network shares (KB 962007) | [20][21] |
| [`T1568.002`](/mitre/techniques/T1568-002.md) | Domain Generation Algorithms | command-and-control | Listed (S0608) | Conficker (ATT&CK object) | [20] |
| [`T1046`](/mitre/techniques/T1046.md) | Network Service Discovery | discovery | Listed (S0608) | Conficker (ATT&CK object) | [20] |
| [`T1105`](/mitre/techniques/T1105.md) | Ingress Tool Transfer | command-and-control | Listed (S0608, S0092) | Conficker; Agent.btz (ATT&CK objects) | [20][24] |
| [`T1112`](/mitre/techniques/T1112.md) | Modify Registry | defense-impairment, persistence | Listed (S0608) | Conficker (ATT&CK object) | [20] |
| [`T1124`](/mitre/techniques/T1124.md) | System Time Discovery | discovery | Listed (S0608) | Conficker (ATT&CK object) | [20] |
| [`T1490`](/mitre/techniques/T1490.md) | Inhibit System Recovery | impact | Listed (S0608) | Conficker (ATT&CK object) | [20] |
| [`T1543.003`](/mitre/techniques/T1543-003.md) | Windows Service | persistence, privilege-escalation | Listed (S0608) | Conficker (ATT&CK object) | [20] |
| [`T1547.001`](/mitre/techniques/T1547-001.md) | Registry Run Keys / Startup Folder | persistence, privilege-escalation | Listed (S0608) | Conficker (ATT&CK object) | [20] |
| [`T1027`](/mitre/techniques/T1027.md) | Obfuscated Files or Information | stealth | Listed (S0608) | Conficker (ATT&CK object) | [20] |
| [`T1685`](/mitre/techniques/T1685.md) | Disable or Modify Tools | defense-impairment | Listed (S0608); Described | Conficker disabled Windows Defender, Automatic Updates, BITS and Error Reporting (KB 962007) | [20][21] |
| [`T1052.001`](/mitre/techniques/T1052-001.md) | Exfiltration over USB | exfiltration | Listed (S0092) | Agent.btz (ATT&CK object; 2008 infection reportedly) | [24] |
| [`T1560.003`](/mitre/techniques/T1560-003.md) | Archive via Custom Method | collection | Listed (S0092) | Agent.btz (ATT&CK object) | [24] |
| [`T1016`](/mitre/techniques/T1016.md) | System Network Configuration Discovery | discovery | Listed (S0092) | Agent.btz (ATT&CK object) | [24] |
| [`T1033`](/mitre/techniques/T1033.md) | System Owner/User Discovery | discovery | Listed (S0092) | Agent.btz (ATT&CK object) | [24] |
| [`T1092`](/mitre/techniques/T1092.md) | Communication Through Removable Media | command-and-control | Described | Fanny's USB-based command channel into air-gapped networks (compiled Jul 2008; Kaspersky, 2015) | [39] |
| [`T1190`](/mitre/techniques/T1190.md) | Exploit Public-Facing Application | initial-access | Described | SQL injection wave on ASP and ASP.NET sites (24 Jun); the SQL vulnerability exploited in Georgia (Aug); Lithuania's vulnerable hosting server (Jun to Jul; exploitation Inferred) | [7][38] |
| [`T1189`](/mitre/techniques/T1189.md) | Drive-by Compromise | initial-access | Described | Compromised sites forwarding visitors to malware (24 Jun); the delivery of the Internet Explorer data binding exploit is not described (Inferred) | [7][25] |
| [`T1203`](/mitre/techniques/T1203.md) | Exploitation for Client Execution | execution | Described | Internet Explorer CVE-2008-4844 exploited at release (17 Dec); Adobe CVE-2008-2992 and CVE-2008-0655 in KEV (exploitation not dated) | [25][26][22][19] |
| [`T1566.001`](/mitre/techniques/T1566-001.md) | Spearphishing Attachment | initial-access | Described | OHHDL lures posing as fellow Tibetans and co-workers (investigated Sep) | [35] |
| [`T1204.002`](/mitre/techniques/T1204-002.md) | Malicious File | execution | Described | OHHDL malicious attachments | [35] |
| [`T1056.001`](/mitre/techniques/T1056-001.md) | Keylogging | collection, credential-access | Described | OHHDL samples (F-Secure, per the Cambridge report) | [35] |
| [`T1005`](/mitre/techniques/T1005.md) | Data from Local System | collection | Described | OHHDL samples' file search and retrieval | [35] |
| [`T1114`](/mitre/techniques/T1114.md) | Email Collection | collection | Inferred | OHHDL mail stolen in transit; the report describes interception, not collection from a mailbox, so the fit is this study's reading | [35] |
| [`T1498`](/mitre/techniques/T1498.md) | Network Denial of Service | impact | Described | Georgia (8 to 28 Aug); Walker and Gembe indictment (2 Oct, alleged) | [38][14] |
| [`T1498.001`](/mitre/techniques/T1498-001.md) | Direct Network Flood | impact | Described | RFE/RL Belarus, about 50,000 fake pings a second (26 to 28 Apr) | [38] |
| [`T1491.002`](/mitre/techniques/T1491-002.md) | External Defacement | impact | Described | Lithuania, more than 300 sites (28 Jun to 2 Jul); Georgia's presidential site (by 11 Aug); RBN-linked defacements per Network World (Reported) | [38][11] |
| [`T1584.005`](/mitre/techniques/T1584-005.md) | Botnet | resource-development | Described | A botnet offered for sale, more than 100,000 computers damaged (21 Aug, alleged) | [52] |
| [`T1669`](/mitre/techniques/T1669.md) | Wi-Fi Networks | initial-access | Described | Gonzalez ring's wardriving into retailers' wireless networks (5 Aug, alleged) | [51] |
| [`T1040`](/mitre/techniques/T1040.md) | Network Sniffing | credential-access, discovery | Described | Sniffers on retailers' processing networks (5 Aug, alleged); packet sniffer on Dave & Buster's registers (12 May, alleged); Heartland's malicious software on data crossing its network (Inferred) | [51][49][12] |
| [`T1110`](/mitre/techniques/T1110.md) | Brute Force | credential-access | Described | Wyndham administrator account brute-forced (Apr, alleged); Conficker's tripped lockout policies (Inferred) | [57][21] |

Left out on purpose: T1078 Valid Accounts for Wyndham, because the court's recital describes the guessing, not the later use of the account in enough detail [57]. T1048 Exfiltration Over Alternative Protocol for Wyndham's transfer to a Russian domain, because the channel is not described [57]. A technique for the Palin e-mail case, because a password reset through security questions on a personal web mail account has no clean ATT&CK technique and the record names no other step [53]. Hannaford, whose court record as read gives no method [56]. The YouTube prefix hijack, a routing incident [2]. DNS cache poisoning, which has a CAPEC pattern but no clean ATT&CK technique [8]. The Debian OpenSSL flaw and the MD5 rogue CA research, which are weaknesses and research, not attacks in the record; T1588.004 Digital Certificates is not bound because no one is recorded using the rogue certificate [5][30]. Clickjacking, which has no recorded 2008 exploitation [73]. The Regin GSM log, whose commands the record opened here does not describe at technique level [42]. GhostNet beyond the Cambridge account, because Citizen Lab's summary names no technique [36]. CVE-2008-3431 in VirtualBox, which KEV names an insufficient input validation vulnerability, with no dated exploitation; no technique is bound [19].

### Techniques ATT&CK lists for Equation, a group tied to 2008 only through Fanny

ATT&CK draws these from later analyses, not from a dated 2008 event, and does not list Fanny, so they are not in this study's Navigator layer (Confirmed [40]; Inferred).

| Id | Name (ATT&CK v20.0) | Tactic(s) | Object | Basis | Sources |
|---|---|---|---|---|---|
| [`T1480.001`](/mitre/techniques/T1480-001.md) | Environmental Keying | stealth | G0020 Equation | Listed (group) | [40] |
| [`T1564.005`](/mitre/techniques/T1564-005.md) | Hidden File System | stealth | G0020 Equation | Listed (group) | [40] |
| [`T1120`](/mitre/techniques/T1120.md) | Peripheral Device Discovery | discovery | G0020 Equation | Listed (group) | [40] |
| [`T1542.002`](/mitre/techniques/T1542-002.md) | Component Firmware | stealth, persistence | G0020 Equation | Listed (group) | [40] |

### ATT&CK for ICS

No 2008 event in the record opened here is an ICS intrusion. The Hatch shutdown was a software-update fault, Order No. 706 is regulation, and the early Stuxnet components are dated only to "as early as November 2008" with no ICS behavior tied to that date (Reported [62]; Confirmed [60][41]). ATT&CK lists three ICS techniques for Conficker, recorded here for completeness; the record opened for this study does not tie them to a 2008 event, so no ICS layer is saved (Confirmed [20]; Demonstrated [76]). The library has no generated pages for ICS techniques, so the ids are plain text.

| Id | Name (ATT&CK for ICS v20.0) | Tactic | Object | Basis | Sources |
|---|---|---|---|---|---|
| T0826 | Loss of Availability | impact | S0608 Conficker | Listed (not tied to 2008) | [20][76] |
| T0828 | Loss of Productivity and Revenue | impact | S0608 Conficker | Listed (not tied to 2008) | [20][76] |
| T0847 | Replication Through Removable Media | initial-access | S0608 Conficker | Listed (not tied to 2008) | [20][76] |

### ATT&CK groups, software and campaigns

| Object | Id | Binding | Sources |
|---|---|---|---|
| Conficker | [S0608](/mitre/software/S0608.md) | Bound: ATT&CK dates first detection to October 2008 (from secondary sources) and lists 13 Enterprise techniques, all in the layer | [20][76] |
| Agent.btz | [S0092](/mitre/software/S0092.md) | Bound with a caveat: ATT&CK says it "reportedly" infected US military networks in 2008; Lynn names no malware, so the Buckshot Yankee link is Inferred | [24][23][33] |
| Stuxnet | [S0603](/mitre/software/S0603.md) | Bound with a caveat: ATT&CK says some components were used as early as November 2008; no technique is tied to 2008 here | [41] |
| Regin | [S0019](/mitre/software/S0019.md) | Bound with a caveat: Kaspersky's GSM log covers April to May 2008; ATT&CK's techniques for Regin are not tied to 2008 here | [42] |
| Green Lambert | [S0690](/mitre/software/S0690.md) | Bound with a caveat: Kaspersky dates the Lamberts' tools to at least 2008; no 2008 operation is named | [43] |
| Equation | [G0020](/mitre/groups/G0020.md) | Bound with a caveat: through Fanny (compiled July 2008), which ATT&CK does not list; ATT&CK gives the group no dates | [39][40] |
| APT29 | [G0016](/mitre/groups/G0016.md) | Bound with a caveat: ATT&CK says active since at least 2008; no 2008 operation named | [44] |
| Axiom | [G0001](/mitre/groups/G0001.md) | Bound with a caveat: since at least 2008 per ATT&CK; no 2008 operation named | [45] |
| BRONZE BUTLER | [G0060](/mitre/groups/G0060.md) | Bound with a caveat: since at least 2008 per ATT&CK; no 2008 operation named | [46] |
| FIN5 | [G0053](/mitre/groups/G0053.md) | Bound with a caveat: since at least 2008 per ATT&CK; no 2008 operation named | [76] |
| APT28 | [G0007](/mitre/groups/G0007.md) | Context only: active since at least 2004 per ATT&CK; no 2008 operation named | [47] |
| Turla | [G0010](/mitre/groups/G0010.md) | Not bound to the 2008 breach: ATT&CK does not list S0092 for Turla, and Kaspersky calls the shared indicators insufficient | [34][33] |
| gh0st RAT | [S0032](/mitre/software/S0032.md) | Not bound to GhostNet: the ATT&CK entry does not mention GhostNet, Tibet or 2008 | [37] |
| Night Dragon | [C0002](/mitre/campaigns/C0002.md) | Not bound: the nearest campaign in the library's data, first seen November 2009 | [76] |

No campaign object is bound: the library's campaign data has none first seen in 2008 (Demonstrated [76]). The library's software and group data has no object for Gimmiv.A, Fanny, the GhostNet operators, the Georgia, Belarus or Lithuania attacks, the Gonzalez ring or DarkMarket (Demonstrated [76]).

### CWE and CAPEC

Rows marked NVD carry the CWE NVD lists; others are this study's classes (Inferred). Names are those in the library's CWE and CAPEC data, and every CAPEC listed has a page under `/mitre/capec/` (Demonstrated [75][76]). The library has no per-CWE generated pages, so CWE ids are plain text; the [CWE reference](/CWE_REFERENCE.md) is the library's entry point. The CAPEC column uses the CAPEC ids the library's CWE or technique data relates, unless marked as this study's pairing (Demonstrated [76]).

| CWE | Weakness (library name) | Basis | 2008 record | CAPEC |
|---|---|---|---|---|
| CWE-338 | Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG) | NVD | Debian OpenSSL (CVE-2008-0166) | [CAPEC-97](/mitre/capec/CAPEC-97.md) Cryptanalysis (study's pairing; the library relates no CAPEC to CWE-338) |
| CWE-331 | Insufficient Entropy | NVD | DNS cache poisoning (CVE-2008-1447) | [CAPEC-142](/mitre/capec/CAPEC-142.md) DNS Cache Poisoning (study's pairing); the library relates [CAPEC-59](/mitre/capec/CAPEC-59.md) Session Credential Falsification through Prediction |
| CWE-94 | Improper Control of Generation of Code | NVD | MS08-067 (CVE-2008-4250) | None assigned (the library relates CAPEC-242, CAPEC-35 and CAPEC-77; none is specific to this flaw) |
| CWE-119 | Improper Restriction of Operations within the Bounds of a Memory Buffer | NVD | MS08-067 (CVE-2008-4250) | [CAPEC-100](/mitre/capec/CAPEC-100.md) Overflow Buffers |
| CWE-787 | Out-of-bounds Write | NVD | Adobe util.printf() (CVE-2008-2992) | None (the library relates none) |
| CWE-399 | (as NVD lists it; not in the library's CWE data) | NVD | Internet Explorer data binding (CVE-2008-4844) | None assigned |
| CWE-352 | Cross-Site Request Forgery | NVD | Cisco IOS HTTP administration (CVE-2008-4128) | [CAPEC-62](/mitre/capec/CAPEC-62.md) Cross Site Request Forgery |
| CWE-89 | Improper Neutralization of Special Elements used in an SQL Command | Study's class | SQL injection wave (Advisory 954462); Georgia's exploited SQL vulnerability | [CAPEC-66](/mitre/capec/CAPEC-66.md) SQL Injection |
| CWE-328 | Use of Weak Hash | Study's class | MD5 rogue CA research (no CVE) | [CAPEC-459](/mitre/capec/CAPEC-459.md) Creating a Rogue Certification Authority Certificate (study's pairing; the library relates CAPEC-461 and CAPEC-68 to CWE-328) |
| CWE-1021 | Improper Restriction of Rendered UI Layers or Frames | Study's class | Flash clickjacking (APSA08-08) | [CAPEC-103](/mitre/capec/CAPEC-103.md) Clickjacking |
| none bound | (brute force) | Library data | Wyndham's administrator account | [CAPEC-112](/mitre/capec/CAPEC-112.md) Brute Force (the library lists it on T1110) |
| none bound | (removable media) | Library data | Agent.btz, Conficker, Fanny | [CAPEC-457](/mitre/capec/CAPEC-457.md) USB Memory Attacks (the library lists it on T1091 and T1092) |
| none bound | (sniffing) | Library data | Gonzalez ring; Dave & Buster's | [CAPEC-158](/mitre/capec/CAPEC-158.md) Sniffing Network Traffic (the library lists it on T1040) |
| none bound | (phishing) | Library data | OHHDL lures | [CAPEC-163](/mitre/capec/CAPEC-163.md) Spear Phishing (the library lists it on T1566.001) |
| none bound | (flooding) | Library data | RFE/RL Belarus; Georgia | [CAPEC-125](/mitre/capec/CAPEC-125.md) Flooding (the library lists it on T1498.001) |
| none bound | (scanning) | Library data | Conficker | [CAPEC-300](/mitre/capec/CAPEC-300.md) Port Scanning (the library lists it on T1046) |

NVD's CWE ids for flaws disclosed before September may have been assigned after CWE 1.0 (Confirmed [59]; Inferred for the assignment dates).

### D3FEND countermeasures

The technique-to-countermeasure links come from the library's D3FEND data; pairing them with the 2008 record is this study's reading (Demonstrated [76]; Inferred). Every page exists under `/mitre/d3fend/` (Demonstrated [75]).

| Technique or event from the record | D3FEND countermeasures (D3FEND tactic) | 2008 analogue |
|---|---|---|
| T1210, T1203 | [Process Segment Execution Prevention](/mitre/d3fend/process-segment-execution-prevention.md) (Harden); [Segment Address Offset Randomization](/mitre/d3fend/segment-address-offset-randomization.md) (Harden); [Stack Frame Canary Validation](/mitre/d3fend/stack-frame-canary-validation.md) (Harden) | MS08-067 and the browser and Reader flaws [16][26][22]; no 2008 source opened here names these controls (Inferred) |
| T1210 | [Network Traffic Filtering](/mitre/d3fend/network-traffic-filtering.md) (Isolate); [Connection Attempt Analysis](/mitre/d3fend/connection-attempt-analysis.md) (Detect) | Microsoft's workaround of blocking TCP 139 and 445 at the firewall [16]; [Inbound Traffic Filtering](/mitre/d3fend/inbound-traffic-filtering.md) is this study's pairing for that workaround, which the library's data links to T1190 rather than T1210 (Inferred) |
| T1091, T1052.001 | [IO Port Restriction](/mitre/d3fend/io-port-restriction.md) (Isolate); [Hardware Component Inventory](/mitre/d3fend/hardware-component-inventory.md) (Model) | Agent.btz, Conficker's AutoPlay spread and Fanny [23][21][39] |
| T1190 | [Database Query String Analysis](/mitre/d3fend/database-query-string-analysis.md) (Detect); [Inbound Traffic Filtering](/mitre/d3fend/inbound-traffic-filtering.md) (Isolate) | The SQL injection wave; Microsoft's UrlScan request filtering [7] |
| T1189 | [URL Reputation Analysis](/mitre/d3fend/url-reputation-analysis.md) (Detect); [Network Traffic Filtering](/mitre/d3fend/network-traffic-filtering.md) (Isolate) | Visitors forwarded to malware sites [7] |
| T1566.001 | [Email Filtering](/mitre/d3fend/email-filtering.md) (Isolate); [Sender Reputation Analysis](/mitre/d3fend/sender-reputation-analysis.md) (Detect); [File Analysis](/mitre/d3fend/file-analysis.md) (Detect) | OHHDL lures [35] |
| T1204.002 | [Executable Allowlisting](/mitre/d3fend/executable-allowlisting.md) (Isolate); [File Analysis](/mitre/d3fend/file-analysis.md) (Detect) | OHHDL attachments [35] |
| T1040 | [DNS Traffic Analysis](/mitre/d3fend/dns-traffic-analysis.md) (Detect), the only countermeasure the library links | Retail sniffers [51] |
| DNS cache poisoning (no technique) | [DNS Traffic Analysis](/mitre/d3fend/dns-traffic-analysis.md) (study's pairing) | CVE-2008-1447 [8] (Inferred) |
| Debian OpenSSL keys (no technique) | [Credential Rotation](/mitre/d3fend/credential-rotation.md); [Reissue Credential](/mitre/d3fend/reissue-credential.md) (study's pairings) | Debian's instruction to regenerate all key material [5] (Inferred) |
| MD5 rogue CA (no technique) | [Certificate Analysis](/mitre/d3fend/certificate-analysis.md) (study's pairing) | The rogue CA certificate [29] (Inferred) |
| MS08-067 and MS08-078 patching | [Software Update](/mitre/d3fend/software-update.md) (study's pairing) | The out-of-band bulletins [16][26] (Inferred) |
| EINSTEIN 2 (no technique) | [Network Traffic Signature Analysis](/mitre/d3fend/network-traffic-signature-analysis.md) (study's pairing) | CNCI initiative 2 [1] (Inferred) |

The library links T1498, T1110, T1568.002 and T1021.002 to no D3FEND countermeasure (Demonstrated [76]). ATT&CK mitigation pages exist for [M1051 Update Software](/mitre/mitigations/M1051.md), [M1042 Disable or Remove Feature or Program](/mitre/mitigations/M1042.md), [M1037 Filter Network Traffic](/mitre/mitigations/M1037.md), [M1034 Limit Hardware Installation](/mitre/mitigations/M1034.md), [M1036 Account Use Policies](/mitre/mitigations/M1036.md), [M1032 Multi-factor Authentication](/mitre/mitigations/M1032.md), [M1041 Encrypt Sensitive Information](/mitre/mitigations/M1041.md) and [M1050 Exploit Protection](/mitre/mitigations/M1050.md) (Demonstrated [75]). MS08-067's service-disabling workaround maps most closely to M1042, its port blocking to M1037, removable-media control to M1034, Wyndham's guessed administrator account to M1036 and M1032, and its unencrypted data to M1041 (Inferred [16][21][57]).

### Navigator layer

The study's Enterprise techniques are saved as one ATT&CK Navigator layer pinned to ATT&CK v20, [navigator/library-layers/chronicle-2008.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/chronicle-2008.json), in the format of the existing chronicle layers: domain enterprise-attack, navigator 4.9, layer 4.5, described as a curated case-study layer and not an official MITRE mapping (Demonstrated [77]). It lists the 33 techniques in the Enterprise table under each tactic they carry in v20.0, 39 technique-tactic entries in all, and is listed on [the Navigator layers page](/navigator/index.md). The four Equation techniques and the three ICS techniques are not in it. Scores show the basis, not severity, in the house scale set by the 2016 chronicle: 100 where an ATT&CK object prints the id, 70 where a primary source describes the behavior and this study assigns the id, 50 where only a Reported source supports it, and 40 for an Inferred mapping (Demonstrated [77]). The 17 techniques listed for S0608 or S0092 score 100, with a comment noting that Agent.btz's 2008 infection is "reportedly" in ATT&CK and Conficker's October date comes from ATT&CK's secondary sources; T1114 scores 40; every other row scores 70. Each entry's comment names the source numbers in the Sources table below.

## Cross-cutting themes

**Foundations failed quietly.** A random number generator, a DNS transaction model and a hash function all turned out to be weaker than the systems built on them assumed, and in each case the fix needed more than a patch: key regeneration, port randomization with DNSSEC to follow, and CAs moving off MD5 (Confirmed [5][8][30]).

**The worm came back.** MS08-067 shipped out of band with a warning that the flaw could be used in a wormable exploit, and Conficker followed (Confirmed [16][21]; Reported [20]).

**Card data left through networks around the core.** Store wireless networks, register terminals, a hotel network joined to the corporate one and a processor's own network, as alleged, and in two cases the card brands noticed first (Confirmed as alleged [51][49][57][56]; Confirmed [12]; the pattern is Inferred).

**Politically timed attacks recurred.** Belarus in April (a flood), Lithuania in June and July (defacements) and Georgia in August (both) each came at a political moment, each with an origin CCDCOE could not settle (Confirmed [38]).

**The state record arrived late.** Buckshot Yankee was told in 2010, GhostNet in 2009, Fanny in 2015, Regin in 2014 and the Lamberts in 2017 (Confirmed [23][36][39][42][43]).

**The rules and the vocabulary arrived together.** CNCI, NATO's policy, CCDCOE, FERC's CIP order, PL 110-326, PCI DSS 1.2, CWE 1.0, TLS 1.2 and two NIST guides all date from 2008 (Confirmed [1][66][67][60][63][13][59][69][68][71]).

### What is overstated and what is understated

This section is the study's reading of the record (Inferred).

- **Overstated: "DNS was broken in 2008".** US-CERT said port randomization reduced practicality, not that the attack was solved or unsolvable, and named DNSSEC as the full fix; OMB mandated it for .gov the same summer [8][70].
- **Overstated: the MD5 rogue CA as an attack.** It was research, the certificate was backdated to have expired, and Microsoft knew of no active attacks [29][30].
- **Overstated: Conficker as a 2008 event.** ATT&CK dates its detection to October 2008 from secondary sources, but its mass spread belongs to 2009; NVD's primary record dates only Gimmiv.A's exploitation to October 2008 [20][18].
- **Overstated: "Turla hacked the Pentagon".** The official account names "a foreign intelligence agency", ATT&CK lists no group for Agent.btz, and Kaspersky calls the shared indicators insufficient [23][24][33].
- **Overstated: "Georgia was Russia's first cyberwar".** CCDCOE found no evident link to the Russian administration; the "campaign by Russia" line is the victim government's, and the direction claims are third-party analysts' [38].
- **Overstated: "largest ever" labels.** "The largest hacking and identity theft case" is DOJ's own 2008 framing, and "the most significant breach of U.S. military computers ever" is DoD's [51][23].
- **Overstated: the precision of ids on 2008 events.** Every ATT&CK and CAPEC id here is retrospective, CWE 1.0 came in September, and KEV came 14 to 18 years later [59][19].
- **Understated: the SQL injection wave.** It had no CVE because it was not a product bug, so CVE-centred histories miss it, yet Microsoft treated it as an advisory-level event [7].
- **Understated: the defender plumbing.** NVD's first CWE mappings, CWE 1.0, the first advisory with a CWE id, SP 800-115, SP 800-61 Rev. 1, the Exploitability Index, TLS 1.2 and CNCI's Trusted Internet Connections and EINSTEIN 2 shaped later years more than any single breach [59][71][68][74][69][1].
- **Understated: Hannaford and Wyndham.** Both 2008 intrusions sit in court records rather than headlines, and the library had no primary on Hannaford before this study [56][57][78].
- **Understated: Belarus and Lithuania.** They show the Georgia pattern two to four months earlier [38].
- **Understated: the invisible operations.** Fanny, Regin, the Lamberts and early Stuxnet components were active in 2008 by later accounts, and none was public at the time [39][42][43][41].
- **Understated: the KEV tail.** MS08-067 entered KEV on 20 May 2026 and a Cisco IOS flaw on 13 July 2026 [19].

### Discrepancies in the record

- **Conficker's first month.** October 2008 per ATT&CK, drawn from secondary sources; other accounts of the month were not checked; NVD dates Gimmiv.A's exploitation of the same flaw to October [20][18].
- **Exploitation of MS08-067 at release.** Microsoft says it knew of "limited, targeted attacks"; CERT/CC says the flaw was "being currently exploited in the wild" [16][17].
- **The Debian flaw's start.** Debian gives the version, 0.9.8c-1; CERT/CC gives a date, 17 September 2006; NVD gives the range 0.9.8c-1 up to before 0.9.8g-9 [5][3][4].
- **CERT/CC dates.** VU#925211 was public on 13 May and published on 15 May; VU#493881 public on 9 December and published on 11 December; VU#836068 public on 30 December and published on 31 December [3][25][31].
- **Agent.btz's dates.** Origins 2007 and public in late 2008 per Kaspersky; "reportedly" 2008 per ATT&CK; Lynn gives 2008 and no name [33][24][23].
- **Stuxnet's start.** "As early as November 2008" for some components per ATT&CK; the [Stuxnet](/case-studies/STUXNET.md) study records Stuxnet 0.5, submitted to a public scanning service in November 2007 [41][78].
- **Georgia's attribution.** No evident state link (CCDCOE's finding), "a cyber warfare campaign by Russia" (Georgia's foreign ministry), government or military priming (Carr and Jackson, as quoted), RBN services (Menn, per Network World) [38][11].
- **GhostNet's attribution.** The Cambridge conclusion names agents of the Chinese government; Citizen Lab says the evidence circumstantially points to China and that the attackers are unknown [35][36].
- **The US and Romania counts.** The release gives 38 individuals, while its two indictments charge 33 and 7; the overlap is this study's reading [50].
- **The undercover name.** The FBI writes "Master Splyntr"; the [Four Books on Cybercrime](/case-studies/CYBERCRIME_FOUR_BOOKS.md) study, quoting Poulsen, writes "Master Splynter" [15][78].
- **Hannaford's numbers.** "Up to 4.2 million" cards and "about 1,800" fraud cases are the plaintiffs' allegations as the court recited them [56].
- **Heartland's timing.** The breach was "in 2008"; the evidence was found in the week before 20 January 2009 [12].

## Sources

Sources were opened on 12 November 2026, except source 6 on 13 November, and the library data checks were run on 13 November 2026, as the Opened column shows. All are checked as of 13 November 2026. Grade is the source's evidence grade as used in this study. Addresses shown as code rather than as links refuse automated link checkers (the two sec.gov addresses of Heartland's filing, the ftc.gov TJX matter page and Adobe's advisory); copy them into a browser to open them.

| # | Source | URL | Opened | Grade |
|---|---|---|---|---|
| 1 | The White House (archived), national cybersecurity initiative (CNCI) page | https://obamawhitehouse.archives.gov/issues/foreign-policy/cybersecurity/national-initiative | 2026-11-12 | Confirmed |
| 2 | RIPE NCC, YouTube Hijacking: A RIPE NCC RIS case study | https://www.ripe.net/publications/news/industry-developments/youtube-hijacking-a-ripe-ncc-ris-case-study | 2026-11-12 | Confirmed |
| 3 | CERT/CC, VU#925211, Debian and Ubuntu OpenSSL packages contain a predictable random number generator | https://kb.cert.org/vuls/id/925211 | 2026-11-12 | Confirmed |
| 4 | NVD, CVE-2008-0166 (API record and detail page) | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2008-0166 ; https://nvd.nist.gov/vuln/detail/CVE-2008-0166 | 2026-11-12 | Confirmed |
| 5 | Debian, DSA-1571-1 openssl, security announcement | https://lists.debian.org/debian-security-announce/2008/msg00152.html | 2026-11-12 | Confirmed |
| 6 | Debian security tracker, DSA-1571-1 | https://security-tracker.debian.org/tracker/DSA-1571-1 | 2026-11-13 | Confirmed |
| 7 | Microsoft Security Advisory 954462, Rise in SQL Injection Attacks Exploiting Unverified User Data Input, 24 Jun 2008 | https://learn.microsoft.com/en-us/security-updates/securityadvisories/2008/954462 | 2026-11-12 | Confirmed |
| 8 | CERT/CC, VU#800113, Multiple DNS implementations vulnerable to cache poisoning | https://kb.cert.org/vuls/id/800113 | 2026-11-12 | Confirmed |
| 9 | Microsoft Security Bulletin MS08-037, 8 Jul 2008 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-037 | 2026-11-12 | Confirmed |
| 10 | NVD, CVE-2008-1447 (API record and detail page) | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2008-1447 ; https://nvd.nist.gov/vuln/detail/CVE-2008-1447 | 2026-11-12 | Confirmed |
| 11 | Network World, review of Joseph Menn's Fatal System Error, 26 Jan 2010 | https://www.networkworld.com/article/771585/security-book-examines-how-u-s-mobsters-russian-gangsters-have-rampaged-across-the-internet.html | 2026-11-12 | Reported |
| 12 | Heartland Payment Systems, Form 8-K of 20 Jan 2009 with Exhibits 99.1 to 99.3 (SEC EDGAR) | `https://www.sec.gov/Archives/edgar/data/1144354/000136231009000509/0001362310-09-000509.txt` ; `https://www.sec.gov/Archives/edgar/data/1144354/000136231009000509/c79618exv99w1.htm` | 2026-11-12 | Confirmed |
| 13 | PCI Security Standards Council, PCI DSS version 1.2 release | https://listings.pcisecuritystandards.org/pdfs/pr_080930_PCIDSSv1-2.pdf | 2026-11-12 | Confirmed |
| 14 | US Attorney's Office, C.D. Cal., release 08-135, 2 Oct 2008 | https://www.justice.gov/archive/usao/cac/Pressroom/pr2008/135.html | 2026-11-12 | Confirmed |
| 15 | FBI, Dark Market undercover operation story, 20 Oct 2008 | https://archives.fbi.gov/archives/news/stories/2008/october/darkmarket_102008 | 2026-11-12 | Confirmed |
| 16 | Microsoft Security Bulletin MS08-067, 23 Oct 2008 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-067 | 2026-11-12 | Confirmed |
| 17 | CERT/CC, VU#827267 (MS08-067 Server service overflow) | https://kb.cert.org/vuls/id/827267 | 2026-11-12 | Confirmed |
| 18 | NVD, CVE-2008-4250 (API record and detail page) | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2008-4250 ; https://nvd.nist.gov/vuln/detail/CVE-2008-4250 | 2026-11-12 | Confirmed |
| 19 | CISA, Known Exploited Vulnerabilities catalog (JSON feed, version 2026.11.10) | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | 2026-11-12 | Confirmed |
| 20 | MITRE ATT&CK, S0608 Conficker | https://attack.mitre.org/software/S0608/ | 2026-11-12 | Confirmed (the object and its techniques); Reported (the October detection date) |
| 21 | Microsoft Support, KB 962007 (Conficker worm) | https://support.microsoft.com/kb/962007 | 2026-11-12 | Confirmed |
| 22 | CERT/CC, VU#593409, Adobe Reader and Acrobat util.printf() stack buffer overflow | https://kb.cert.org/vuls/id/593409 | 2026-11-12 | Confirmed |
| 23 | William J. Lynn III, Defending a New Domain, Foreign Affairs, Sep/Oct 2010 (opening section) | https://www.foreignaffairs.com/articles/united-states/2010-09-01/defending-new-domain | 2026-11-12 | Confirmed (official's published statement) |
| 24 | MITRE ATT&CK, S0092 Agent.btz | https://attack.mitre.org/software/S0092/ | 2026-11-12 | Confirmed (the object and its techniques); Reported (the 2008 infection) |
| 25 | US-CERT alert on the Microsoft Internet Explorer data binding vulnerability, 17 Dec 2008 (archived on cisa.gov; points to VU#493881) | https://www.cisa.gov/news-events/alerts/2008/12/17/microsoft-internet-explorer-data-binding-vulnerability | 2026-11-12 | Confirmed |
| 26 | Microsoft Security Bulletin MS08-078, 17 Dec 2008 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-078 | 2026-11-12 | Confirmed |
| 27 | NVD, CVE-2008-4844 | https://nvd.nist.gov/vuln/detail/CVE-2008-4844 | 2026-11-12 | Confirmed |
| 28 | Sotirov, Stevens, Appelbaum, Lenstra, Molnar, Osvik and de Weger, MD5 considered harmful today (Eindhoven copy) | https://www.win.tue.nl/hashclash/rogue-ca/ | 2026-11-12 | Confirmed |
| 29 | The same research, Marc Stevens's copy | https://marc-stevens.nl/research/hashclash/rogue-ca/ | 2026-11-12 | Confirmed |
| 30 | Microsoft Security Advisory 961509, Research proves feasibility of collision attacks against MD5, 30 Dec 2008 | https://learn.microsoft.com/en-us/security-updates/securityadvisories/2008/961509 | 2026-11-12 | Confirmed |
| 31 | CERT/CC, VU#836068, MD5 vulnerable to collision attacks | https://kb.cert.org/vuls/id/836068 | 2026-11-12 | Confirmed |
| 32 | ThreatExpert, Agent.btz: A Threat That Hit Pentagon, 30 Nov 2008 | http://blog.threatexpert.com/2008/11/agentbtz-threat-that-hit-pentagon.html | 2026-11-12 | Reported |
| 33 | Kaspersky (Alexander Gostev), Agent.btz: a Source of Inspiration?, 12 Mar 2014 | https://securelist.com/agent-btz-a-source-of-inspiration/58551/ | 2026-11-12 | Confirmed (vendor's analysis) |
| 34 | MITRE ATT&CK, G0010 Turla | https://attack.mitre.org/groups/G0010/ | 2026-11-12 | Confirmed |
| 35 | Nagaraja and Anderson, The snooping dragon: social-malware surveillance of the Tibetan movement, University of Cambridge UCAM-CL-TR-746, Mar 2009 | https://www.cl.cam.ac.uk/techreports/UCAM-CL-TR-746.pdf | 2026-11-12 | Confirmed (investigators' report) |
| 36 | Information Warfare Monitor (Citizen Lab and SecDev), Tracking GhostNet, 28 Mar 2009 (summary page) | https://citizenlab.ca/2009/03/tracking-ghostnet-investigating-a-cyber-espionage-network/ | 2026-11-12 | Confirmed |
| 37 | MITRE ATT&CK, S0032 gh0st RAT | https://attack.mitre.org/software/S0032/ | 2026-11-12 | Confirmed |
| 38 | CCDCOE (Tikk, Kaska and Vihul), International Cyber Incidents: Legal Considerations, 2010 | https://ccdcoe.org/uploads/2018/10/legalconsiderations_0.pdf | 2026-11-12 | Confirmed (CCDCOE's findings); Reported (statements and analysts it quotes) |
| 39 | Kaspersky, Equation: The Death Star of Malware Galaxy, 16 Feb 2015 | https://securelist.com/equation-the-death-star-of-malware-galaxy/68750/ | 2026-11-12 | Confirmed (vendor's analysis) |
| 40 | MITRE ATT&CK, G0020 Equation | https://attack.mitre.org/groups/G0020/ | 2026-11-12 | Confirmed |
| 41 | MITRE ATT&CK, S0603 Stuxnet | https://attack.mitre.org/software/S0603/ | 2026-11-12 | Confirmed |
| 42 | Kaspersky, Regin: nation-state ownage of GSM networks, 24 Nov 2014 | https://securelist.com/regin-nation-state-ownage-of-gsm-networks/67741/ | 2026-11-12 | Confirmed (vendor's analysis) |
| 43 | Kaspersky, Unraveling the Lamberts Toolkit, 11 Apr 2017 | https://securelist.com/unraveling-the-lamberts-toolkit/77990/ | 2026-11-12 | Confirmed (vendor's analysis) |
| 44 | MITRE ATT&CK, G0016 APT29 | https://attack.mitre.org/groups/G0016/ | 2026-11-12 | Confirmed |
| 45 | MITRE ATT&CK, G0001 Axiom (read from the library's `data/attack/groups.jsonl` mirror) | https://attack.mitre.org/groups/G0001 | 2026-11-12 | Confirmed |
| 46 | MITRE ATT&CK, G0060 BRONZE BUTLER (read from the library's mirror) | https://attack.mitre.org/groups/G0060 | 2026-11-12 | Confirmed |
| 47 | MITRE ATT&CK, G0007 APT28 (read from the library's mirror) | https://attack.mitre.org/groups/G0007 | 2026-11-12 | Confirmed |
| 48 | US Department of Justice, Ralsky indictment unsealed, 3 Jan 2008 | https://www.justice.gov/archive/opa/pr/2008/January/08_crm_003.html | 2026-11-12 | Confirmed |
| 49 | US Department of Justice, Dave & Buster's charges, 12 May 2008 | https://www.justice.gov/archive/opa/pr/2008/May/08-crm-403.html | 2026-11-12 | Confirmed |
| 50 | US Department of Justice, 38 charged in the US and Romania, 19 May 2008 | https://www.justice.gov/archive/opa/pr/2008/May/08-odag-434.html | 2026-11-12 | Confirmed |
| 51 | US Department of Justice, release 08-689, retail hacking and identity theft charges, 5 Aug 2008 | https://www.justice.gov/archive/opa/pr/2008/August/08-ag-689.html | 2026-11-12 | Confirmed |
| 52 | US Department of Justice, botnet sale charge, 21 Aug 2008 | https://www.justice.gov/archive/opa/pr/2008/August/08-crm-739.html | 2026-11-12 | Confirmed |
| 53 | US Department of Justice, e-mail account access indictment, 8 Oct 2008 | https://www.justice.gov/archive/opa/pr/2008/October/08-crm-910.html | 2026-11-12 | Confirmed |
| 54 | House of Lords, McKinnon v Government of the United States [2008] UKHL 59, 30 Jul 2008 | https://publications.parliament.uk/pa/ld200708/ldjudgmt/jd080730/mckinn-1.htm | 2026-11-12 | Confirmed |
| 55 | Electronic Frontier Foundation, MBTA v. Anderson case page | https://www.eff.org/cases/mbta-v-anderson | 2026-11-12 | Reported |
| 56 | US Court of Appeals for the First Circuit, Anderson v. Hannaford Bros. Co., 20 Oct 2011 | http://media.ca1.uscourts.gov/pdf.opinions/10-2384P-01A.pdf | 2026-11-12 | Confirmed (as the court recites the allegations) |
| 57 | US Court of Appeals for the Third Circuit, FTC v. Wyndham Worldwide Corp., 24 Aug 2015 | https://www2.ca3.uscourts.gov/opinarch/143514p.pdf | 2026-11-12 | Confirmed (as the court recites the allegations) |
| 58 | Federal Trade Commission, matter 072-3055, The TJX Companies | `https://www.ftc.gov/legal-library/browse/cases-proceedings/072-3055-tjx-companies-inc-matter` | 2026-11-12 | Confirmed |
| 59 | MITRE CWE, news archive 2008 | https://cwe.mitre.org/news/archives/news2008.html | 2026-11-12 | Confirmed |
| 60 | Federal Register, FERC Order No. 706, Mandatory Reliability Standards for Critical Infrastructure Protection, 7 Feb 2008 | https://www.federalregister.gov/documents/2008/02/07/E8-1317/mandatory-reliability-standards-for-critical-infrastructure-protection | 2026-11-12 | Confirmed |
| 61 | Federal Register, FERC proposed rule, 25 Sep 2008 | https://www.federalregister.gov/documents/2008/09/25/E8-22198/mandatory-reliability-standards-for-critical-infrastructure-protection | 2026-11-12 | Confirmed |
| 62 | NIST SP 800-82 Rev. 3, Guide to Operational Technology Security, incident appendix | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-82r3.pdf | 2026-11-12 | Reported (NIST relays a news report) |
| 63 | Public Law 110-326 (H.R. 5938), 26 Sep 2008 | https://www.govinfo.gov/content/pkg/PLAW-110publ326/html/PLAW-110publ326.htm | 2026-11-12 | Confirmed |
| 64 | CSIS, Securing Cyberspace for the 44th Presidency, 8 Dec 2008 | https://www.csis.org/analysis/securing-cyberspace-44th-presidency | 2026-11-12 | Confirmed |
| 65 | Council Directive 2008/114/EC of 8 December 2008 (legislation.gov.uk contents page) | https://www.legislation.gov.uk/eudr/2008/114/contents | 2026-11-12 | Confirmed |
| 66 | NATO, Cyber defence topic page | https://www.nato.int/cps/en/natohq/topics_78170.htm | 2026-11-12 | Confirmed |
| 67 | CCDCOE, About us | https://ccdcoe.org/about-us/ | 2026-11-12 | Confirmed |
| 68 | NIST, SP 800-61 Rev. 1, Computer Security Incident Handling Guide | https://csrc.nist.gov/pubs/sp/800/61/r1/final | 2026-11-12 | Confirmed |
| 69 | IETF, RFC 5246, The Transport Layer Security (TLS) Protocol Version 1.2 | https://www.rfc-editor.org/rfc/rfc5246 | 2026-11-12 | Confirmed |
| 70 | OMB, M-08-23, Securing the Federal Government's Domain Name System Infrastructure | https://www.whitehouse.gov/wp-content/uploads/legacy_drupal_files/omb/memoranda/2008/m08-23.pdf | 2026-11-12 | Confirmed |
| 71 | NIST, SP 800-115, Technical Guide to Information Security Testing and Assessment | https://csrc.nist.gov/pubs/sp/800/115/final | 2026-11-12 | Confirmed |
| 72 | Chromium Blog, A new approach to browser security: the Google Chrome Sandbox, 2 Oct 2008 (title and date) | https://blog.chromium.org/2008/10/new-approach-to-browser-security-google.html | 2026-11-12 | Confirmed (title and date only) |
| 73 | Adobe, APSA08-08, Flash Player workaround available for Clickjacking issue | `https://www.adobe.com/support/security/advisories/apsa08-08.html` | 2026-11-12 | Confirmed |
| 74 | Microsoft Security Bulletin Summary for October 2008 | https://learn.microsoft.com/en-us/security-updates/securitybulletinsummaries/2008/ms08-oct | 2026-11-12 | Confirmed |
| 75 | TeamStarWolf library, `mitre/` page tree (technique, group, software, campaign, CAPEC, D3FEND and mitigation pages) | https://github.com/TeamStarWolf/TeamStarWolf/tree/main/mitre | 2026-11-12; 2026-11-13 | Confirmed; Demonstrated |
| 76 | TeamStarWolf library, ATT&CK and weakness data files (`data/attack/`, `data/attack/ics/`, `data/weaknesses/`) | https://github.com/TeamStarWolf/TeamStarWolf/tree/main/data | 2026-11-13 | Demonstrated |
| 77 | TeamStarWolf library, chronicle Navigator layers (`navigator/library-layers/chronicle-2016.json` and the later years) | https://github.com/TeamStarWolf/TeamStarWolf/tree/main/navigator | 2026-11-13 | Demonstrated |
| 78 | TeamStarWolf library, case studies on main (home studies named in the text) | https://github.com/TeamStarWolf/TeamStarWolf/tree/main/case-studies | 2026-11-12; 2026-11-13 | Confirmed (for the fact that a study is the home) |

*© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.*

*© The MITRE Corporation. Includes material from the Common Weakness Enumeration (CWE™), used under the CWE Terms of Use. https://cwe.mitre.org/*

*© The MITRE Corporation. Includes material from the Common Attack Pattern Enumeration and Classification (CAPEC™), used under the CAPEC Terms of Use. https://capec.mitre.org/*

*© The MITRE Corporation. Includes material from MITRE D3FEND™, used under the D3FEND Terms of Use. https://d3fend.mitre.org/*

*The terms for every MITRE dataset used here are recorded in [THIRD_PARTY_NOTICES.md](/THIRD_PARTY_NOTICES.md).*

## Related references

- [Notable Incidents](/NOTABLE_INCIDENTS.md), [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [CVE Reference](/CVE_REFERENCE.md)
- [CWE Reference](/CWE_REFERENCE.md), [CAPEC Reference](/CAPEC_REFERENCE.md), [D3FEND Reference](/D3FEND_REFERENCE.md), [Cryptography](/CRYPTOGRAPHY_REFERENCE.md), [Certificate Trust Incident Response](/CERTIFICATE_TRUST_INCIDENT_RESPONSE_REFERENCE.md), [Network Security Architecture](/NETWORK_SECURITY_ARCHITECTURE.md), [GRC and Compliance](/GRC_COMPLIANCE_REFERENCE.md), [Vulnerability Management](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [Incident Response](/INCIDENT_RESPONSE_REFERENCE.md), [ICS/OT Security](/ICS_OT_SECURITY_REFERENCE.md)
- Home studies: [E-Commerce Threats](/case-studies/ECOMMERCE_THREATS.md); [Four Books on Cybercrime](/case-studies/CYBERCRIME_FOUR_BOOKS.md); [Stuxnet](/case-studies/STUXNET.md); [Russia-attributed threat actors](/case-studies/THREAT_ACTORS_RUSSIA.md); [China-attributed threat actors](/case-studies/THREAT_ACTORS_CHINA.md); [United States-attributed threat actors](/case-studies/THREAT_ACTORS_UNITED_STATES.md); [Other state-attributed actors](/case-studies/THREAT_ACTORS_OTHER_STATES.md); [The Hacker and the State](/case-studies/HACKER_AND_THE_STATE_CASES.md); [Sandworm operations](/case-studies/SANDWORM_OPERATIONS.md); [The Zero-Day Trade and Its Fallout](/case-studies/ZERO_DAY_MARKET_EVENTS.md); [Ransomware ecosystem](/case-studies/RANSOMWARE_ECOSYSTEM.md); [APT41](/case-studies/APT41_PUBLIC_RECORD.md); [ICS attacks and advisories](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md); [Log4Shell](/case-studies/LOG4SHELL.md); [SolarWinds SUNBURST](/case-studies/SOLARWINDS_SUNBURST.md); [npm supply-chain attacks](/case-studies/NPM_SUPPLY_CHAIN_ATTACKS.md); [Hugging Face supply chain](/case-studies/HUGGING_FACE_SUPPLY_CHAIN.md); [The Year 2005 in Intrusions](/case-studies/CHRONICLE_2005.md) (TJX's first intrusion in July 2005, before the 2008 charges)
- Series: [1993](/case-studies/CHRONICLE_1993.md), [1994](/case-studies/CHRONICLE_1994.md), [1995](/case-studies/CHRONICLE_1995.md), [1996](/case-studies/CHRONICLE_1996.md), [1997](/case-studies/CHRONICLE_1997.md), [1998](/case-studies/CHRONICLE_1998.md), [1999](/case-studies/CHRONICLE_1999.md), [2000](/case-studies/CHRONICLE_2000.md), [2001](/case-studies/CHRONICLE_2001.md), [2002](/case-studies/CHRONICLE_2002.md), [2003](/case-studies/CHRONICLE_2003.md), [2004](/case-studies/CHRONICLE_2004.md), [2005](/case-studies/CHRONICLE_2005.md), [2016](/case-studies/CHRONICLE_2016.md), [2017](/case-studies/CHRONICLE_2017.md), [2018](/case-studies/CHRONICLE_2018.md), [2019](/case-studies/CHRONICLE_2019.md), [2020](/case-studies/CHRONICLE_2020.md), [2021](/case-studies/CHRONICLE_2021.md), [2022](/case-studies/CHRONICLE_2022.md), [2023](/case-studies/CHRONICLE_2023.md), [2024](/case-studies/CHRONICLE_2024.md), [2025](/case-studies/CHRONICLE_2025.md), [2026](/case-studies/CHRONICLE_2026.md)
- Techniques: [T1210 Exploitation of Remote Services](/mitre/techniques/T1210.md), [T1091 Replication Through Removable Media](/mitre/techniques/T1091.md), [T1021.002 SMB/Windows Admin Shares](/mitre/techniques/T1021-002.md), [T1568.002 Domain Generation Algorithms](/mitre/techniques/T1568-002.md), [T1046 Network Service Discovery](/mitre/techniques/T1046.md), [T1105 Ingress Tool Transfer](/mitre/techniques/T1105.md), [T1112 Modify Registry](/mitre/techniques/T1112.md), [T1124 System Time Discovery](/mitre/techniques/T1124.md), [T1490 Inhibit System Recovery](/mitre/techniques/T1490.md), [T1543.003 Windows Service](/mitre/techniques/T1543-003.md), [T1547.001 Registry Run Keys / Startup Folder](/mitre/techniques/T1547-001.md), [T1027 Obfuscated Files or Information](/mitre/techniques/T1027.md), [T1685 Disable or Modify Tools](/mitre/techniques/T1685.md), [T1052.001 Exfiltration over USB](/mitre/techniques/T1052-001.md), [T1560.003 Archive via Custom Method](/mitre/techniques/T1560-003.md), [T1016 System Network Configuration Discovery](/mitre/techniques/T1016.md), [T1033 System Owner/User Discovery](/mitre/techniques/T1033.md), [T1092 Communication Through Removable Media](/mitre/techniques/T1092.md), [T1190 Exploit Public-Facing Application](/mitre/techniques/T1190.md), [T1189 Drive-by Compromise](/mitre/techniques/T1189.md), [T1203 Exploitation for Client Execution](/mitre/techniques/T1203.md), [T1566.001 Spearphishing Attachment](/mitre/techniques/T1566-001.md), [T1204.002 Malicious File](/mitre/techniques/T1204-002.md), [T1056.001 Keylogging](/mitre/techniques/T1056-001.md), [T1005 Data from Local System](/mitre/techniques/T1005.md), [T1114 Email Collection](/mitre/techniques/T1114.md), [T1498 Network Denial of Service](/mitre/techniques/T1498.md), [T1498.001 Direct Network Flood](/mitre/techniques/T1498-001.md), [T1491.002 External Defacement](/mitre/techniques/T1491-002.md), [T1584.005 Botnet](/mitre/techniques/T1584-005.md), [T1669 Wi-Fi Networks](/mitre/techniques/T1669.md), [T1040 Network Sniffing](/mitre/techniques/T1040.md), [T1110 Brute Force](/mitre/techniques/T1110.md); Equation object techniques [T1480.001](/mitre/techniques/T1480-001.md), [T1564.005](/mitre/techniques/T1564-005.md), [T1120](/mitre/techniques/T1120.md), [T1542.002](/mitre/techniques/T1542-002.md)
- CAPEC: [CAPEC-59](/mitre/capec/CAPEC-59.md), [CAPEC-62](/mitre/capec/CAPEC-62.md), [CAPEC-66](/mitre/capec/CAPEC-66.md), [CAPEC-97](/mitre/capec/CAPEC-97.md), [CAPEC-100](/mitre/capec/CAPEC-100.md), [CAPEC-103](/mitre/capec/CAPEC-103.md), [CAPEC-112](/mitre/capec/CAPEC-112.md), [CAPEC-125](/mitre/capec/CAPEC-125.md), [CAPEC-142](/mitre/capec/CAPEC-142.md), [CAPEC-158](/mitre/capec/CAPEC-158.md), [CAPEC-163](/mitre/capec/CAPEC-163.md), [CAPEC-300](/mitre/capec/CAPEC-300.md), [CAPEC-457](/mitre/capec/CAPEC-457.md), [CAPEC-459](/mitre/capec/CAPEC-459.md)
- Groups, software and campaigns: Conficker [S0608](/mitre/software/S0608.md); Agent.btz [S0092](/mitre/software/S0092.md); Stuxnet [S0603](/mitre/software/S0603.md); Regin [S0019](/mitre/software/S0019.md); Green Lambert [S0690](/mitre/software/S0690.md); gh0st RAT [S0032](/mitre/software/S0032.md); Equation [G0020](/mitre/groups/G0020.md); APT29 [G0016](/mitre/groups/G0016.md); Axiom [G0001](/mitre/groups/G0001.md); BRONZE BUTLER [G0060](/mitre/groups/G0060.md); FIN5 [G0053](/mitre/groups/G0053.md); APT28 [G0007](/mitre/groups/G0007.md); Turla [G0010](/mitre/groups/G0010.md); Night Dragon [C0002](/mitre/campaigns/C0002.md)
- [Navigator layers](/navigator/index.md), including this study's layer, [chronicle-2008.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/chronicle-2008.json)
