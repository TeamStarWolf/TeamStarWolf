# The Year 2018 in Intrusions: A Dated Record

*A TeamStarWolf case study. Published 11 November 2026; every source checked as of that date.*

[All case studies](/case-studies/README.md) · Related: [Notable Incidents](/NOTABLE_INCIDENTS.md), [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [CVE Reference](/CVE_REFERENCE.md), [Ransomware Defense](/RANSOMWARE_DEFENSE_REFERENCE.md), [ICS and OT Security](/ICS_OT_SECURITY_REFERENCE.md), [Supply Chain Security](/SUPPLY_CHAIN_SECURITY.md) · Home studies for events summarized here: [Sandworm: the operations in the public record](/case-studies/SANDWORM_OPERATIONS.md) (Olympic Destroyer, VPNFilter and the NotPetya attribution), [Russia-attributed threat actors](/case-studies/THREAT_ACTORS_RUSSIA.md) (Dragonfly, the router campaign, the GRU indictments, LoJax and the TRITON attribution), [North Korea-attributed threat actors](/case-studies/THREAT_ACTORS_NORTH_KOREA.md) (Park Jin Hyok, APT38 and FASTCash), [Iran-attributed threat actors](/case-studies/THREAT_ACTORS_IRAN.md) (the Mabna Institute and SamSam), [China-attributed threat actors](/case-studies/THREAT_ACTORS_CHINA.md) (APT10 and Cloud Hopper, the Jiangsu MSS case and Thrip), [npm supply-chain attacks](/case-studies/NPM_SUPPLY_CHAIN_ATTACKS.md) (event-stream) · Series: [The Year 2016 in Intrusions](/case-studies/CHRONICLE_2016.md), [The Year 2017 in Intrusions](/case-studies/CHRONICLE_2017.md), [The Year 2019 in Intrusions](/case-studies/CHRONICLE_2019.md), [The Year 2020 in Intrusions](/case-studies/CHRONICLE_2020.md), [The Year 2021 in Intrusions](/case-studies/CHRONICLE_2021.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Threat intelligence analysts, security leaders and defenders who want the history behind current threats

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 83 min (19,051 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want a dated record of the major intrusions of 2018, you need Olympic Destroyer, VPNFilter, the year's indictments and the Marriott and Facebook disclosures side by side, or you want the defender lessons that still apply

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [Part 1: the year as a dated timeline](#part-1-the-year-as-a-dated-timeline), [Part 13: the defender view](#part-13-the-defender-view)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Notable Incidents](/NOTABLE_INCIDENTS.md), [Threat Actors](/THREAT_ACTORS.md), [Sandworm: The Operations in the Public Record](/case-studies/SANDWORM_OPERATIONS.md), [The Year 2019 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2019.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive summary

The year 2018 opened with a flaw in the processors themselves. On 3 January, Google Project Zero published speculative-execution attacks that let one program read memory it should never see, three CVEs it had reported to Intel, AMD and ARM seven months earlier [1]. Five weeks later, malware built only to destroy took down systems behind the PyeongChang Winter Olympics during the opening ceremony; Cisco Talos found no theft and named no actor [5]. On 28 February, GitHub went offline for five minutes under a DDoS that peaked at 1.35 terabits per second, reflected off exposed memcached servers [9].

The rest of the year is a record of governments naming names. The United Kingdom and the United States attributed the 2017 NotPetya attack to the Russian military on 15 February [7][8]. US and UK agencies published a joint warning that Russian state-sponsored actors were taking over routers and switches worldwide without zero-days or malware [19]. Talos estimated that VPNFilter sat on at least 500,000 home and small-office devices, and the Justice Department obtained a court order for the FBI to seize its command domain the same day [22][23]. The Justice Department charged GRU officers twice (July and October), nine Iranians tied to an institute working for the IRGC (March), a North Korean programmer for WannaCry, Sony and the Bangladesh Bank theft (September), Jiangsu MSS officers (October), the two Iranians behind SamSam (November) and two APT10 members acting with the MSS Tianjin bureau (December) [29][21][13][36][49][54][58]. Treasury added sanctions in March, June, September, November and December, and in November published bitcoin addresses for the first time [12][61][37][55][60].

The largest data disclosures of the year were not all intrusions. Marriott said on 30 November that an intruder had been inside the Starwood guest network since 2014, with up to about 500 million guests in the database [56]. Facebook said up to 87 million people's data may have been shared with Cambridge Analytica, data misuse rather than an intrusion, and in September that attackers had stolen access tokens through its View As feature, a count it revised to about 30 million people in October [17][39][75]. TSMC's August virus outbreak was, by TSMC's own account, a misoperation during software installation, not an attack [34].

This study is the dated record of that year, built only from sources opened on 11 November 2026. Olympic Destroyer, VPNFilter, the GRU cases, Dragonfly, APT10, the North Korean cases, SamSam and event-stream each have a home study in this collection; this record gives each a summary and a link, and keeps the dates, costs and controls together. Every row carries its date, the source that supports it and an evidence grade.

Evidence grade: advisories, indictments (as allegations), sanctions, regulator findings and settlements, company filings and statements, the vendor's own research, CVE, NVD, vendor-advisory and KEV records, the live ATT&CK pages and the library's own data files are **Confirmed** from the issuing body. A vendor's attribution assessment that no government record states (FireEye on TRITON, Dragos on XENOTIME, Check Point on Ryuk) is **Reported**. Where this study draws its own conclusion, or maps described behavior to ATT&CK on its own reading, it says **Inferred**.

### Key facts at a glance

| Field | Value |
|---|---|
| Period | 1 January to 31 December 2018, plus the earlier conduct that 2018 charges and disclosures describe (2010 to 2017) and the later records, from 2019 to 2026, that close 2018 events |
| Processor flaws | CVE-2017-5753, CVE-2017-5715 and CVE-2017-5754 (Spectre variants 1 and 2, Meltdown), disclosed 3 January 2018 after notice to Intel, AMD and ARM on 1 June 2017; none of the three (CVE-2017-5753, CVE-2017-5715, CVE-2017-5754) is in KEV [1][2][86] |
| Destructive attack of the year | Olympic Destroyer at the PyeongChang opening ceremony, 9 February 2018: destructive only, no exfiltration, recovery within about 12 hours; charged to GRU officers in October 2020 [5][6] |
| DDoS of the year | GitHub, 28 February 2018: 1.35 Tbps and 126.9 million packets per second of memcached reflection; full outage 17:21 to 17:26 UTC [9] |
| Device botnet | VPNFilter: at least 500,000 SOHO routers and NAS devices in at least 54 countries (Talos estimate); C2 domain seized 23 May 2018 [22][23] |
| Data disclosures | Marriott (Starwood), up to about 500 million guests, about 327 million with passport or other details, 30 November; MyFitnessPal about 150 million accounts, 29 March; MyHeritage 92,283,889 users, 4 June; Facebook View As about 30 million people with tokens stolen (revised 12 October) [56][14][25][75] |
| Ransomware case of the year | SamSam: over 200 victims, over $6 million in ransom and over $30 million in losses alleged from December 2015 to September 2018 (indictment, 28 November) [54] |
| Reported crime | FBI IC3 2018: 351,937 complaints and losses over $2.7 billion; business email compromise 20,373 complaints and $1,297,803,489; ransomware 1,493 complaints and $3,621,857 [65] |
| State charges and attributions | NotPetya to the Russian military (15 Feb); Mabna Institute (23 Mar); 12 GRU officers (13 Jul); Park Jin Hyok (6 Sep); 7 GRU officers and the UK and Dutch exposure (4 Oct); Jiangsu MSS (30 Oct); SamSam (28 Nov); APT10 and the allied attribution to the MSS (20 Dec) [7][8][13][29][36][21][16][49][54][58][59] |
| Rules of the year | CSF 1.1 (16 Apr); California Consumer Privacy Act chaptered (28 Jun); Singapore Cybersecurity Act 2018; EO 13848 (12 Sep); National Cyber Strategy (20 Sep); CISA Act (16 Nov); Australia's Assistance and Access Act [79][80][81][82][83][84][85] |
| 2018 CVEs later in KEV | 89 entries in catalog 2026.11.10, 33 flagged for known ransomware use, none added in 2018 because KEV began on 3 November 2021 [86] |
| This study's MITRE binding | 127 Enterprise and 4 ICS technique rows, 13 groups, 19 software objects and 6 campaigns, CWE and CAPEC bindings for the year's CVEs and advisory conditions, D3FEND pairings, and two Navigator layers (Part 14) |

### Key findings

- **The edge was taken without exploits.** TA18-106A says Russian state-sponsored actors compromised routers and switches worldwide without needing zero-days or malware, through legacy unencrypted protocols, Smart Install, default settings and unpatched devices (Confirmed [19]). Talos counted over 168,000 potentially exposed Smart Install systems (Confirmed [18]), and Talos estimated VPNFilter on at least 500,000 devices whose models all had well-known public vulnerabilities (Confirmed [22]).
- **Credentials did more of the work than malware.** The TA18-074A actors (Dragonfly in Symantec's reporting) harvested hashes through forced SMB authentication and reached networks "where multi-factor authentication was not used"; the Mabna actors sprayed common passwords at single sign-on and email; SamSam came in over RDP with brute-forced or bought credentials; APT10 used stolen MSP administrator credentials (Confirmed [11][77][57][58]). Reading credential theft as the common thread is this study's view (Inferred).
- **Trusted third parties carried the intrusions.** TA18-074A describes staging targets used to reach intended targets, TA18-276B describes MSPs targeted since May 2016, the APT10 indictment describes an MSP campaign reaching clients in at least 12 countries, and a new npm maintainer slipped a malicious dependency into event-stream (Confirmed [11][42][58][73]).
- **Destruction was built for an audience.** Olympic Destroyer deleted shadow copies and recovery options and shut hosts down during an opening ceremony, with no exfiltration (Confirmed [5]); VPNFilter carried a command that destroys the device (Confirmed [22]). Reading both as built to be seen is this study's view (Inferred).
- **Attribution in 2018 was uneven and often late.** Talos named no actor for Olympic Destroyer in February; DOJ charged GRU officers for it in October 2020 (Confirmed [5][6]). DOJ tied VPNFilter to the Sofacy Group, the UK listed it among GRU activities without a separate assessment, and ATT&CK now lists Sandworm Team (Confirmed [23][16][108]).
- **Governments used every instrument at once.** Indictments, sanctions, joint advisories, domain seizures and coordinated public exposure all appear in the same year, and OFAC published digital currency addresses for the first time on 28 November (Confirmed [54][55][23][16]; the reading is Inferred).
- **The biggest numbers were first-day numbers.** Facebook's "almost 50 million" became about 30 million people with stolen tokens two weeks later, and Marriott's figures were maximums ("up to") (Confirmed [39][75][56]).
- **A CVE-2018 id does not mean a 2018 event.** NVD published the FortiOS SSL VPN flaw CVE-2018-13379 on 4 June 2019, and KEV added none of its 89 CVE-2018 entries before 3 November 2021 (Confirmed [105][86]).

### Top recommendations

1. **Put multi-factor authentication on every external interface.** TA18-074A, TA18-086A, AA18-337A and TA18-106A each ask for it (Confirmed [11][77][57][19]).
2. **Treat network devices as assets with owners.** No plaintext management protocols or management interfaces from the internet, Telnet and SNMPv1/v2c off, unique non-default passwords, Smart Install disabled, outbound TFTP blocked, firmware verified and unsupported equipment retired (Confirmed [19]).
3. **Close RDP and SMB at the edge.** Block SMB and WebDAV at the boundary and RDP from untrusted addresses (TA18-074A); audit and disable RDP, put it behind a VPN and keep no open 3389 on public cloud VMs (AA18-337A); block client-to-client SMB by policy (TA18-201A) (Confirmed [11][57][32]).
4. **Bound what a provider can do.** A dedicated certificate-authenticated VPN for MSP access terminated in a DMZ, MSP accounts kept out of Enterprise and Domain Admin groups, scoped and time-limited (Confirmed [42]).
5. **Keep recovery out of reach.** Olympic Destroyer and SamSam both went after recovery; AA18-337A asks for a good backup strategy (Confirmed [5][57]).
6. **Turn logging on before the incident.** PowerShell 5 module, script block and transcription logging and one-year SIEM retention (TA18-074A); 90-day RDP login logs (AA18-337A); baselines of software, logons and transactions on payment switches (TA18-275A) (Confirmed [11][57][40]).
7. **Reboot, reset and patch the home and office edge.** Talos advised factory resets, reboots and patching for VPNFilter, and the FBI told owners to reboot (Confirmed [22][68]).
8. **Separate payment switches and control systems from the business network.** TA18-275A asks for isolated switch servers with mutual TLS on payment links; TA18-074A asks for segmented control systems (Confirmed [40][11]).

## Scope and method

This study covers intrusions, campaigns, exploited vulnerabilities, data disclosures, crime cases and the government response dated to calendar year 2018, plus the earlier conduct that 2018 charges describe and the later records (indictments, ATT&CK objects, catalog entries) that close a 2018 event. It follows the method of the [case studies collection](/case-studies/README.md): primary sources first, every claim graded, numbers as the source states them, and every source opened on 11 November 2026.

| Grade | Meaning in this study |
|---|---|
| Confirmed | The primary source was opened and states the fact: a government advisory, statement or law, a court or charging document (cited as allegations), a sanctions notice, a regulator finding or settlement, a company filing or statement, the vendor's own research or bulletin, a CVE, NVD or KEV record, the live ATT&CK page, or the library's own data files |
| Reported | The fact rests on a vendor's attribution assessment that no government record opened here states, or on a story the primary record denies |
| Demonstrated | Public proof-of-concept code exists; it shows a flaw can be used, not that it was. No 2018 claim in this study rests on this grade |
| Inferred | This study's own reasoning or arithmetic, or an ATT&CK mapping that no source prints, labelled where it appears |

Limits that a reader should know:

- **DOJ releases read through other copies.** The live justice.gov pages serve a bot check. The Infraud, Mabna, GRU (July and October), VPNFilter, FIN7, Park Jin Hyok, Jiangsu MSS, SamSam, APT10 and 2020 GRU releases were read through the Justice Department's own press-release API or from Internet Archive snapshots of the earlier `/opa/pr/` address. The cited URL is the canonical address.
- **Pages that rendered only in part.** Marriott's newsroom release showed only its title and date at the cited address, and its body was read from the archived 2018 address [70]; the 8-K exhibit [56] carries the same facts. The two Europol pages rendered only their summary text, so the Carbanak leader's arrest date and the webstresser details beyond the summary were not checked [66][67]. The Cathay Pacific date comes from the page metadata [48].
- **Pages that did not open.** Bloomberg Businessweek's "Big Hack" story (403), McAfee's Operation Sharpshooter report (403), the UK ICO penalty notices for British Airways, Marriott and Ticketmaster (403), British Airways' incident page (empty), Quora's statement (403) and Atlanta's own statement (403) did not open. This study makes no claim that rests on them: the Big Hack claim appears only as the companies' denials describe it, Sharpshooter only through ATT&CK's C0013 object, and Atlanta only as a victim the SamSam indictment names. British Airways, Quora, Coincheck, Shamoon 3 at Saipem and the Singapore government's SingHealth inquiry are not covered, because no primary record for them was opened.
- **Counts are the source's counts.** Indictment totals are allegations; FBI complaint totals are self-reported and a floor [65]; Talos's VPNFilter count is an estimate [22]; first-day breach counts were later revised where noted.
- **Attribution is dated to its statement.** A vendor's "we believe" stays a belief; an indictment is an allegation; today's ATT&CK attribution is not written back into 2018.
- **Home studies.** Olympic Destroyer, VPNFilter and the NotPetya attribution live in [the Sandworm study](/case-studies/SANDWORM_OPERATIONS.md); Dragonfly, the router campaign, the GRU indictments, LoJax and the TRITON attribution in [the Russia-attributed actors study](/case-studies/THREAT_ACTORS_RUSSIA.md); Park Jin Hyok, APT38 and FASTCash in [the North Korea-attributed actors study](/case-studies/THREAT_ACTORS_NORTH_KOREA.md); Mabna and SamSam in [the Iran-attributed actors study](/case-studies/THREAT_ACTORS_IRAN.md); APT10, the Jiangsu MSS case and Thrip in [the China-attributed actors study](/case-studies/THREAT_ACTORS_CHINA.md); event-stream in [the npm supply-chain study](/case-studies/NPM_SUPPLY_CHAIN_ATTACKS.md). Each is summarized here (Confirmed for the home studies' coverage [122]).
- **Tradecraft is described at advisory level.** Technique names and ids only. TA18-074A and TA18-106A print command lines and signatures; none is reproduced here, and no exploit details, payload strings or ransom notes appear.

## Part 1: the year as a dated timeline

One row per event or report. The date is the event date where the source gives one, otherwise the publication date. Later records that close a 2018 event follow in a second table.

| Date | Event | Thread | Grade | Sources |
|---|---|---|---|---|
| 2018-01 (from) | Symantec's Thrip investigation starts with an alert at a Southeast Asian telecom where PsExec was used to install Infostealer.Catchamas (published 19 Jun 2018) | State | Confirmed | [26] |
| 2018-01-03 | Google Project Zero publishes speculative-execution side channels CVE-2017-5753, CVE-2017-5715 and CVE-2017-5754 (Meltdown), reported to Intel, AMD and ARM on 1 Jun 2017; NVD publishes them on 4 Jan; the researchers say they do not know whether they were abused | Vulnerability | Confirmed | [1][2] |
| 2018-01-10 | NVD publishes CVE-2018-0802, Office Equation Editor remote code execution (CWE-787); KEV lists it with known ransomware use | Vulnerability | Confirmed | [103][86] |
| 2018-01-13 | AWS bulletin AWS-2018-013: EC2 Amazon Linux instances launched on or after this date include the patched kernel | Vulnerability, cloud | Confirmed | [3] |
| 2018-01-29 | NVD publishes CVE-2018-0101, Cisco ASA SSL VPN double free (CWE-415) | Vulnerability | Confirmed | [87] |
| 2018-02-06 | NVD publishes CVE-2018-4878, Adobe Flash use-after-free (CWE-416); KEV lists it with known ransomware use | Vulnerability | Confirmed | [88][86] |
| 2018-02-07 | DOJ unseals the Infraud Organization indictment: 36 charged, 13 arrested in the US, Australia, the UK, France, Italy, Kosovo and Serbia; over $530 million actual and over $2.2 billion intended losses alleged; group created October 2010 | Crime | Confirmed | [4] |
| 2018-02-08 | NVD publishes CVE-2018-6789, Exim base64d buffer overflow (CWE-120); KEV lists it with known ransomware use | Vulnerability | Confirmed | [104][86] |
| 2018-02-09 | Olympic Destroyer (S0365) disrupts PyeongChang Winter Olympics systems during the opening ceremony; the Olympic website goes offline and reporters' Wi-Fi fails; recovery within about 12 hours (Talos, 12 Feb, no actor named). Home study: [Sandworm](/case-studies/SANDWORM_OPERATIONS.md) | Destructive | Confirmed | [5] |
| 2018-02-15 | The UK attributes the June 2017 NotPetya attack to the Russian Government, specifically the Russian military; the White House attributes it to the Russian military and calls it the most destructive and costly cyber-attack in history | Government | Confirmed | [7][8] |
| 2018-02 (late) | An unauthorized party acquires MyFitnessPal data: about 150 million accounts, usernames, email addresses and hashed passwords (most bcrypt); no payment data (Under Armour 8-K, 29 Mar) | Data breach | Confirmed | [14] |
| 2018-02-27 | Cloudflare describes memcached amplification over UDP port 11211 and reports 260 Gbps of inbound memcached traffic at peak | DDoS | Confirmed | [10] |
| 2018-02-28 | GitHub is unavailable from 17:21 to 17:26 UTC, intermittently to 17:30, under a memcached-reflected DDoS from over a thousand ASNs, peaking at 1.35 Tbps and 126.9 Mpps; traffic moved to Akamai | DDoS | Confirmed | [9] |
| 2018-03 | Google finds and patches a Google+ People API bug that potentially exposed profiles of up to 500,000 accounts to up to 438 apps (disclosed 8 Oct) | Data exposure | Confirmed | [45] |
| 2018-03 | GRU spearphishing attempt against the UK Foreign and Commonwealth Office (UK, 4 Oct) | State | Confirmed | [16] |
| 2018-03-15 | DHS and FBI alert TA18-074A on Russian government cyber actors targeting government and the energy, nuclear, commercial facilities, water, aviation and critical manufacturing sectors since at least March 2016, through staging targets. Home study: [Russia-attributed actors](/case-studies/THREAT_ACTORS_RUSSIA.md) | State, ICS | Confirmed | [11] |
| 2018-03-15 | Treasury OFAC designates five entities and 19 individuals, including the IRA, the FSB and the GRU, under CAATSA and E.O. 13694, citing 2016 election interference, NotPetya and critical-infrastructure targeting since March 2016 | Government | Confirmed | [12] |
| 2018-03-23 | DOJ charges nine Iranians tied to the Mabna Institute, which it says acted for the IRGC: 144 US and 176 foreign universities in 21 countries, 47 companies, 31+ TB stolen (allegations); OFAC designates the institute and the nine. Home study: [Iran-attributed actors](/case-studies/THREAT_ACTORS_IRAN.md) | State | Confirmed | [13] |
| 2018-03-23 | Public Law 115-141, the Consolidated Appropriations Act, 2018, approved; it carries the CLOUD Act (the CLOUD Act text was not checked) | Government | Confirmed | [78] |
| 2018-03-27 | TA18-086A: password spraying against SSO, federated cloud and email applications, tied to the Mabna indictment | State | Confirmed | [77] |
| 2018-03-28 | Drupal SA-CORE-2018-002 (CVE-2018-7600, "Drupalgeddon2"), Highly critical 24/25, Drupal 7 before 7.58 and Drupal 8 branches; Cisco cisco-sa-20180328-smi2 (CVE-2018-0171, Smart Install, CVSS 9.8) | Vulnerability | Confirmed | [15][90] |
| 2018-03-29 | Under Armour discloses the MyFitnessPal breach, learned of on 25 Mar | Data breach | Confirmed | [14] |
| 2018-04 | Four GRU officers on diplomatic passports attempt a close-access Wi-Fi operation against OPCW networks in The Hague; the Dutch MIVD disrupts it (indictment allegation); the UK also records a GRU attempt on DSTL | State | Confirmed | [21][16] |
| 2018-04-04 | Facebook: data of up to 87 million people may have been improperly shared with Cambridge Analytica; phone and email search disabled after abuse to scrape public profiles (data misuse, not an intrusion) | Data misuse | Confirmed | [17] |
| 2018-04-05 | Talos warns that advanced actors, some believed linked to nation states, are abusing the Cisco Smart Install client protocol, including against critical infrastructure; over 168,000 exposed systems (Shodan) | State, network | Confirmed | [18] |
| 2018-04-16 | US-UK alert TA18-106A (DHS, FBI, NCSC) on Russian state-sponsored exploitation of routers and switches through GRE, Smart Install and SNMP, reported to the US since 2015; NIST releases CSF 1.1 the same day | State, network, government | Confirmed | [19][79] |
| 2018-04-19 | TA18-106A update: an industry partner reports DNS redirection through GRE tunnels. NVD publishes CVE-2018-2628, Oracle WebLogic deserialization (CWE-502), now in KEV | State, vulnerability | Confirmed | [19][92] |
| 2018-04-24 | SEC charges Altaba (formerly Yahoo) with failing to disclose the December 2014 breach; $35 million penalty, neither admitting nor denying. Administrators of webstresser.org arrested under Operation Power Off (Dutch Police and UK NCA with Europol) | Government, crime | Confirmed | [20][67] |
| 2018-05 | GRU spearphishing impersonating Swiss federal authorities targets OPCW staff likely attending a conference in Spiez (UK) | State | Confirmed | [16] |
| 2018-05-04 | NVD publishes CVE-2018-10561, Dasan GPON authentication bypass (CWE-287), in KEV; sibling CVE-2018-10562 in KEV with known ransomware use | Vulnerability | Confirmed | [93] |
| 2018-05-08 and 2018-05-17 | VPNFilter infection spikes in Ukraine (Talos) | State, network | Confirmed | [22] |
| 2018-05-09 | Microsoft fixes CVE-2018-8174 (VBScript engine, CWE-787) and CVE-2018-8120 (Win32k, CWE-404); both in KEV with known ransomware use | Vulnerability | Confirmed | [94][86] |
| 2018-05-23 | Talos publishes VPNFilter: at least 500,000 devices in at least 54 countries, Modbus sniffing, a kill command, BlackEnergy overlap that Talos says "isn't definitive by any means". DOJ obtains orders for the FBI to seize a C2 domain and names the Sofacy Group (APT28). Home study: [Sandworm](/case-studies/SANDWORM_OPERATIONS.md) | State, network | Confirmed | [22][23] |
| 2018-05-25 | TA18-145A and FBI PSA I-052518-PSA tell owners to reboot SOHO routers and NAS devices | Network | Confirmed | [69][68] |
| 2018-05-29 | TA18-149A on HIDDEN COBRA's Joanap backdoor and Brambul SMB worm; 87 compromised Joanap nodes identified | State | Confirmed | [24] |
| 2018-06-04 | MyHeritage: a researcher found email addresses and hashed passwords of 92,283,889 users who signed up through 26 Oct 2017 on a private outside server | Data breach | Confirmed | [25] |
| 2018-06-07 | NVD publishes CVE-2018-0296, Cisco ASA web interface path traversal and DoS (CWE-20, CWE-22), now in KEV | Vulnerability | Confirmed | [95] |
| 2018-06-08 | Criminal complaint against Park Jin Hyok filed under seal (unsealed 6 Sep) | State | Confirmed | [36] |
| 2018-06-11 | OFAC designates Digital Security, ERPScan, Embedi, Kvant Scientific Research Institute and Divetechnoservices, plus three individuals, for supporting the FSB | Government | Confirmed | [61] |
| 2018-06-19 | Symantec reports Thrip (G0076) against satellite communications, geospatial imaging and defense targets in the US and Southeast Asia, traced to three computers in China. Home study: [China-attributed actors](/case-studies/THREAT_ACTORS_CHINA.md) | State | Confirmed | [26] |
| 2018-06-23 | Ticketmaster UK identifies malicious software on a customer-support product hosted by Inbenta; under 5 percent of global customers affected, North America not | Supply chain, e-commerce | Confirmed | [27] |
| 2018-06 (late) | FIN7 member arrested in Lepe, Spain (DOJ, 1 Aug) | Crime | Confirmed | [33] |
| 2018-06-28 | An attacker takes over a Gentoo GitHub organization admin account through a guessable password pattern; California's Consumer Privacy Act is chaptered (Chapter 55), rights from 1 Jan 2020 | Supply chain, government | Confirmed | [74][80] |
| 2018-07 | SingHealth attack, with a reported 1.5 million patient records stolen; Symantec attributes it to Whitefly (G0107) in March 2019 | State, health care | Confirmed (attribution Reported) | [30] |
| 2018-07-04 | Timehop network intrusion: a cloud credential without MFA compromised; names, emails, dates of birth and access tokens of about 21 million users taken | Data breach, cloud | Confirmed | [28] |
| 2018-07-13 | Special Counsel indictment of 12 GRU officers (Units 26165 and 74455) for 2016 election interference (allegations) | State | Confirmed | [29] |
| 2018-07-14 | LabCorp detects suspicious activity on LabCorp Diagnostics systems, takes systems offline, briefly disrupts test processing (8-K, 16 Jul); the SamSam indictment later lists LabCorp | Ransomware, health care | Confirmed | [31][54] |
| 2018-07-20 | TA18-201A: Emotet among the most costly and destructive malware for SLTT governments, up to $1 million per incident | Crime | Confirmed | [32] |
| 2018-08-01 | DOJ announces three FIN7 members in custody: breaches in 47 states and DC, over 15 million card records from over 6,500 POS terminals at over 3,600 locations (allegations) | Crime | Confirmed | [33] |
| 2018-08-02 | NVD publishes CVE-2018-14847, MikroTik RouterOS directory traversal (CWE-22), now in KEV | Vulnerability | Confirmed | [96] |
| 2018-08-03 | TSMC virus outbreak hits computer systems and fab tools in Taiwan; TSMC blames misoperation during software installation for a new tool; about 3 percent hit to Q3 revenue (release of 5 Aug) | Operational incident | Confirmed | [34] |
| 2018-08 (week before 20 Aug) | Microsoft's Digital Crimes Unit takes control of six Strontium (APT28) domains under a court order, including look-alikes of the IRI, the Hudson Institute and the US Senate | State | Confirmed | [35] |
| 2018-08-15 to 2018-12-20 | Microsoft zero-days now in KEV: CVE-2018-8373, 8440, 8453, 8589, 8611 and 8653; KEV marks 8440 and 8453 with known ransomware use | Vulnerability | Confirmed | [97][86] |
| 2018-08-20 | Check Point reports Ryuk in targeted attacks over two weeks, an estimated take over $640,000 and code close to HERMES; a North Korea link only a possibility | Ransomware | Reported | [63] |
| 2018-08-22 | NVD publishes CVE-2018-11776, Apache Struts namespace RCE, in KEV | Vulnerability | Confirmed | [98] |
| 2018-08-31 | Singapore's Cybersecurity Act 2018 (Act 9 of 2018) version dated this day; it provides for designating critical information infrastructure | Government | Confirmed | [81] |
| 2018-09-06 | DOJ unseals the Park Jin Hyok complaint (Lazarus Group, Chosun Expo Joint Venture): Sony (2014), Bangladesh Bank (2016), WannaCry 2.0 (2017); OFAC designates Park and the company. Home study: [North Korea-attributed actors](/case-studies/THREAT_ACTORS_NORTH_KOREA.md) | State | Confirmed | [36][37] |
| 2018-09-08 | Marriott's internal security tool alerts on the Starwood guest reservation database | Data breach | Confirmed | [56] |
| 2018-09-09 | A new maintainer adds malicious flatmap-stream 0.1.1 as a dependency of event-stream 3.3.6, aimed at the Copay build. Home study: [npm supply-chain attacks](/case-studies/NPM_SUPPLY_CHAIN_ATTACKS.md) | Supply chain | Confirmed | [73] |
| 2018-09-12 | Executive Order 13848 on sanctions for foreign interference in US elections signed | Government | Confirmed | [82] |
| 2018-09-20 | National Cyber Strategy signed, described as the first fully articulated US cyber strategy since 2003 | Government | Confirmed | [83] |
| 2018-09-25 | Facebook finds attackers exploited three interacting bugs in View As to steal access tokens; SamSam's most recent alleged attack; NVD publishes CVE-2018-15961, ColdFusion unrestricted upload (CWE-434), now in KEV | Data breach, ransomware, vulnerability | Confirmed | [39][54][99] |
| 2018-09-26 | New York AG announces a record $148 million settlement between Uber and all 50 states and DC over concealing the November 2016 breach of 57 million riders and drivers | Government | Confirmed | [38] |
| 2018-09-27 | ESET publishes LoJax (S0397), the first UEFI rootkit found in the wild, attributed with high confidence to Sednit (APT28) | State | Confirmed (attribution Reported) | [62] |
| 2018-09-28 | Facebook discloses the View As breach, resets tokens for almost 50 million accounts plus 40 million as a precaution, disables View As | Data breach | Confirmed | [39] |
| 2018-10-02 | TA18-275A on HIDDEN COBRA FASTCash: payment switch servers compromised since late 2016; one 2018 incident enabled simultaneous ATM withdrawals in 23 countries | State, financial | Confirmed | [40] |
| 2018-10-03 | FireEye names APT38 (G0082), North Korea's financially motivated group: over $1.1 billion attempted at more than 16 organizations in at least 13 countries since 2014; TA18-276B on APT activity against MSPs since May 2016 | State, financial, supply chain | Confirmed (APT38 attribution Reported) | [41][42] |
| 2018-10-04 | DOJ (W.D. Pa.) indicts seven GRU officers for operations against WADA, USADA, FIFA, IAAF, Westinghouse and the OPCW, Dec 2014 to May 2018 (allegations); the UK, after the Dutch statement, lists 2018 GRU attempts against the FCO, DSTL and OPCW; Apple and AWS deny Bloomberg Businessweek's "Big Hack" story | State | Confirmed (the Big Hack claim itself Reported) | [21][16][43][44] |
| 2018-10-08 | Google discloses the March Google+ API bug and announces the shutdown of consumer Google+ | Data exposure | Confirmed | [45] |
| 2018-10-11 | Five Eyes report AA18-284A on five public tools seen in incidents worldwide: JBiFrost, China Chopper, Mimikatz, PowerShell Empire and HUC Packet Transmitter | Advisory | Confirmed | [46] |
| 2018-10-12 | Facebook revises: about 30 million people actually had tokens stolen | Data breach | Confirmed | [75] |
| 2018-10-17 | ESET discloses GreyEnergy (S0342), a BlackEnergy successor used for three years against energy companies and others in Ukraine and Poland; NVD publishes CVE-2018-10933, libssh authentication bypass (CWE-287), not in KEV | State, ICS, vulnerability | Confirmed | [47][100] |
| 2018-10-23 | FireEye assesses with high confidence that CNIIHM, a Russian government-owned institute, supported the TRITON intrusion activity | State, ICS | Reported | [71] |
| 2018-10-24 | Cathay Pacific discloses unauthorized access to data of up to 9.4 million passengers, including passport and identity card numbers | Data breach | Confirmed | [48] |
| 2018-10-30 | DOJ charges Jiangsu MSS officers Zha Rong and Chai Meng, hackers and insiders, alleging theft of turbofan engine technology from Jan 2010 to May 2015 | State | Confirmed | [49] |
| 2018-11-14 | FireEye detects phishing at more than 20 clients overlapping a suspected APT29 campaign of 9 Nov 2016; ATT&CK records it as campaign C0021 | State | Confirmed | [50][116] |
| 2018-11-16 | Public Law 115-278, the Cybersecurity and Infrastructure Security Agency Act of 2018, approved | Government | Confirmed | [84] |
| 2018-11-19 | Marriott decrypts the data and determines it came from the Starwood guest reservation database | Data breach | Confirmed | [70] |
| 2018-11-26 | npm is notified about event-stream, removes both packages and takes ownership of event-stream | Supply chain | Confirmed | [73] |
| 2018-11-27 | Talos reports DNSpionage against Lebanese and UAE government domains and a Lebanese airline, with DNS redirection, no known actor; EDNY charges eight defendants in the Methbot and 3ve ad-fraud schemes and the FBI sinkholes Kovter domains | State, crime | Confirmed | [51][52][53] |
| 2018-11-28 | DOJ unseals the SamSam indictment (Savandi, Mansouri) and OFAC designates two Iran-based exchangers, publishing two bitcoin addresses for the first time | Ransomware, government | Confirmed | [54][55] |
| 2018-11-30 | Marriott discloses unauthorized access to the Starwood network since 2014: up to about 500 million guests, about 327 million with passport and other details, card numbers AES-128 encrypted with both decryption components possibly taken | Data breach | Confirmed | [56][70] |
| 2018-12 | Australia's Assistance and Access Act 2018 registered as C2018A00148 (assent date not checked) | Government | Confirmed | [85] |
| 2018-12-03 | AA18-337A on SamSam: JexBoss against JBoss in early 2016, then RDP from mid-2016 | Ransomware | Confirmed | [57] |
| 2018-12-05 | NVD publishes CVE-2018-1002105, Kubernetes API server privilege escalation, not in KEV | Vulnerability, cloud | Confirmed | [101] |
| 2018-12-10 | Google says a November Google+ API bug affected about 52.5 million users for six days | Data exposure | Confirmed | [76] |
| 2018-12-11 | NVD publishes CVE-2018-20062, ThinkPHP remote code execution, in KEV | Vulnerability | Confirmed | [102] |
| 2018-12-19 | OFAC designates nine GRU officers of Units 26165 and 74455 and two officers for the 2016 WADA compromise and the OPCW attempts | Government | Confirmed | [60] |
| 2018-12-20 | DOJ unseals the APT10 indictment (Zhu Hua, Zhang Shilong, Tianjin State Security Bureau) and the UK and allies attribute APT 10 to China's MSS. Home study: [China-attributed actors](/case-studies/THREAT_ACTORS_CHINA.md) | State | Confirmed | [58][59] |

Also in 2018, with the exact date not checked: Europol announces the arrest in Alicante, Spain, of the leader of the gang behind the Carbanak and Cobalt attacks on over 100 financial institutions in 40 countries (Confirmed from the page summary [66]); No More Ransom lists a Bitdefender decryptor for GandCrab versions 1, 4 and 5 up to 5.2, release date not checked (Confirmed [64]).

Later records that close a 2018 event:

| Date | Record | Grade | Sources |
|---|---|---|---|
| 2019-01-18 to 2019-06-04 | NVD publishes CVE-2018-15982 (Flash, 18 Jan), CVE-2018-20250 (WinRAR ACE, 5 Feb) and CVE-2018-13379 (FortiOS SSL VPN path traversal, 4 Jun 2019); each belongs to the 2019 record despite its id. See [The Year 2019 in Intrusions](/case-studies/CHRONICLE_2019.md) | Confirmed | [105] |
| 2019-03-06 | Symantec attributes the July 2018 SingHealth attack to Whitefly | Confirmed | [30] |
| 2020-10-19 | DOJ charges six GRU officers; the indictment says Olympic Destroyer disrupted thousands of computers supporting the PyeongChang Games and describes spearphishing of the IOC, athletes and partners from Dec 2017 to Feb 2018. ATT&CK rows on G0034 cite the UK NCSC statement of the same day | Confirmed | [6][109] |
| 2021-11-03 | KEV launches; 17 CVE-2018 entries are added that day, 18 in 2021 in all | Confirmed | [86] |
| 2021-11 and 2025-08-20 | Cisco records in-the-wild exploitation attempts of CVE-2018-0171 and, in 2025, continued exploitation | Confirmed | [90] |
| 2022 | KEV adds 62 CVE-2018 entries, including CVE-2018-8174 on 15 Feb 2022 | Confirmed | [86][94] |
| 2026-01-26 | KEV adds CVE-2018-14634 (Linux kernel), the latest CVE-2018 entry as of catalog 2026.11.10 | Confirmed | [86] |
| Current | ATT&CK G0035 Dragonfly now attributes the group to Russia's FSB Center 16, citing 2022 DOJ and UK sources; G0082 APT38 to the Reconnaissance General Bureau | Confirmed | [106][114] |

## Part 2: Russia

### Olympic Destroyer (summary; home: [Sandworm](/case-studies/SANDWORM_OPERATIONS.md))

Talos published on 12 February what struck the PyeongChang Winter Olympics during the opening ceremony on 9 February. The malware was destructive only, with no exfiltration: it deleted shadow copies and the backup catalog, disabled recovery, cleared logs, wiped writable files on mapped shares and shut systems down, and spread with PsExec and WMI using credentials taken from browsers and LSASS and written into new binaries (Confirmed [5]). The infection vector was unknown; the Olympic website went offline and reporters' Wi-Fi failed, and officials reported recovery within about 12 hours (Confirmed [5]). Talos named no actor. DOJ's October 2020 indictment of six GRU officers says the malware disrupted thousands of computers supporting the Games and describes spearphishing of the IOC, athletes and partners from December 2017 to February 2018 (Confirmed, allegation [6]). ATT&CK lists Olympic Destroyer as S0365 under Sandworm Team (G0034) with 14 techniques (Confirmed [107]).

### The NotPetya attribution and the sanctions

On 15 February the UK judged the Russian military responsible for NotPetya, with the NCSC assessing it "almost certainly responsible", and the White House attributed it to the Russian military as part of the Kremlin's effort to destabilize Ukraine, without hedging (Confirmed [7][8]). On 15 March Treasury designated the FSB, the GRU and six individuals under CAATSA section 224 and the IRA and its associates under E.O. 13694, citing NotPetya and targeting of US energy and other critical sectors since at least March 2016 (Confirmed [12]). On 11 June it designated five Russian entities and three individuals for supporting the FSB's cyber and underwater capabilities, citing NotPetya, intrusions into the US energy grid and router and switch compromises (Confirmed [61]). NotPetya itself is a 2017 event; see [the Sandworm study](/case-studies/SANDWORM_OPERATIONS.md) for its operation and [the 2017 chronicle](/case-studies/CHRONICLE_2017.md) for the attack's dated record.

### Dragonfly and TA18-074A (summary; home: [Russia-attributed actors](/case-studies/THREAT_ACTORS_RUSSIA.md))

TA18-074A attributes a multi-stage campaign, active since at least March 2016, to "Russian government cyber actors" against US government entities and the energy, nuclear, commercial facilities, water, aviation and critical manufacturing sectors (Confirmed [11]). It describes two classes of victim: staging targets, trusted third-party suppliers with less secure networks, and the intended targets reached through them (Confirmed [11]). The tradecraft it names: spearphishing with Office attachments sent from compromised accounts that fetch a remote resource over SMB to harvest hashes; watering holes on trade-publication and ICS-related sites, about half of the known watering holes; password cracking; local administrator accounts disguised as backup accounts; web shells on public email and web servers; a registry change that keeps plaintext credentials in memory; VPN, RDP and OWA access; PsExec; NTDS and SYSTEM hive collection; screenshots through scheduled tasks; and log clearing and tool deletion (Confirmed [11]). On ICS-related hosts the actors accessed SCADA files and copied VNC profiles and HMI screenshots (Confirmed [11]).

The Dragonfly name comes from the alert's citation of Symantec's report, not from a DHS or FBI determination; the link to ATT&CK G0035 is a reading of that citation (Confirmed for the citation [11]; the link Inferred). ATT&CK's G0035 page carries procedure text citing TA18-074A on 41 technique ids, and now attributes the group to Russia's FSB Center 16, citing 2022 DOJ and UK sources (Confirmed [106]). TA18-074A did not name the FSB, and this study does not write that attribution back into 2018 (Inferred).

### The router and switch campaign (summary; home: [Russia-attributed actors](/case-studies/THREAT_ACTORS_RUSSIA.md))

On 5 April Talos warned that advanced actors, some believed to be linked to nation states, were abusing the Cisco Smart Install client protocol, a misuse rather than a vulnerability, including against critical infrastructure, and counted over 168,000 potentially exposed systems (Confirmed [18]). On 16 April DHS, FBI and the UK NCSC published TA18-106A. The US Government assesses that "cyber actors supported by the Russian government" ran a worldwide campaign against routers, switches, firewalls and network intrusion detection systems, and the FBI has high confidence they use compromised routers for man-in-the-middle (Confirmed [19]). The methods are legacy Telnet, HTTP and SNMP, Smart Install abuse, configuration files with password hashes and SNMP community strings pulled to TFTP, brute force and credential reuse, and GRE tunnels that mirror traffic; the alert says the actors needed neither zero-day vulnerabilities nor malware (Confirmed [19]). The US had received reporting on this since 2015, and an update of 19 April reports DNS redirected through GRE tunnels (Confirmed [19]).

### VPNFilter (summary; home: [Sandworm](/case-studies/SANDWORM_OPERATIONS.md))

Talos estimated on 23 May that VPNFilter had infected at least 500,000 Linksys, MikroTik, NETGEAR, TP-Link and QNAP devices in at least 54 countries. Stage 1 survives reboot, some stage 2 versions carry a kill command that destroys the device, and a stage 3 sniffer steals website credentials and monitors Modbus traffic (Confirmed [22]). Infections in Ukraine spiked on 8 and 17 May, and Talos said of the code overlap with BlackEnergy that it "isn't definitive by any means" (Confirmed [22]). Talos had no definitive proof of the exploitation vector, though every affected model had well-known public vulnerabilities (Confirmed [22]). The same day DOJ obtained court orders for the FBI to seize a C2 domain, so the persistent stage 1 would call an FBI server that logs victim addresses for Shadowserver to pass to CERTs and ISPs; DOJ named the controller the Sofacy Group, with aliases including apt28 and sandworm (Confirmed [23]). TA18-145A and the FBI's PSA told owners to reboot (Confirmed [69][68]).

The attribution differs by source. DOJ in May named the Sofacy Group with a mixed alias list; the UK on 4 October dates VPNFilter's infections to October 2017 and lists it among the activities its lead sentence says the GRU is almost certainly responsible for, though the VPNFilter entry itself carries no separate NCSC assessment and points to the April joint alert on "Russian state-sponsored actors"; ATT&CK lists S1010 under Sandworm Team (G0034) through Cyclops Blink reporting rather than direct attribution (Confirmed [23][16][108]). This study states each with its source (Inferred).

### The GRU indictments and the OPCW (summary; home: [Russia-attributed actors](/case-studies/THREAT_ACTORS_RUSSIA.md))

On 13 July the Special Counsel indicted 12 GRU officers. The indictment alleges that Unit 26165 spearphished the Clinton campaign and hacked the DCCC and DNC in 2016, that the documents were released through DCLeaks and Guccifer 2.0, that Unit 74455 helped release them and conspired to hack state boards of elections, secretaries of state and election-technology suppliers, and that infrastructure was paid for in cryptocurrency (Confirmed, allegations [29]). The conduct is from 2016; the charge is the 2018 event.

On 4 October DOJ (W.D. Pa.) indicted seven GRU officers for a conspiracy from about December 2014 to at least May 2018 against WADA, USADA, CCES, IAAF, FIFA and Westinghouse, using spearphishing, spoofed domains, close-access teams on hotel Wi-Fi and leaks under the name "Fancy Bears' Hack Team" (Confirmed, allegations [21]). It alleges that in April 2018 four officers on diplomatic passports went to The Hague for a Wi-Fi operation against OPCW networks, were disrupted by the Dutch MIVD and had planned to target the Spiez laboratory next; the FBI seized the fancybears domains (Confirmed [21]). The UK statement the same day assesses "with high confidence that the GRU was almost certainly responsible" for each listed operation and names the 2018 attempts: the FCO by spearphishing in March, DSTL and the OPCW in April, and OPCW staff in May with a spearphish impersonating Swiss federal authorities ahead of a Spiez conference (Confirmed [16]). The UK lists the GRU's associated names as including APT 28, Fancy Bear, Sofacy, Sednit, Voodoo Bear and Sandworm (Confirmed [16]). In mid-August Microsoft's Digital Crimes Unit took six Strontium domains under a court order, its 12th such action in two years, covering 84 sites (Confirmed [35]). On 19 December Treasury designated nine officers of Units 26165 and 74455, and two officers for WADA and the OPCW attempts (Confirmed [60]).

### LoJax, TRITON and the APT29-like campaign

ESET reported on 27 September that LoJax, the first UEFI rootkit found in the wild, writes to SPI flash and survives OS reinstall and disk replacement, and attributed it "with high confidence" to Sednit (APT28); the victims were government organizations in the Balkans and Central and Eastern Europe (Confirmed for the findings, Reported for the attribution [62]). On 23 October FireEye assessed with high confidence that the TRITON intrusion activity (TEMP.Veles, G0088) was supported by CNIIHM, a Russian government-owned research institute in Moscow (Reported [71]). TRITON itself is a 2017 event; Dragos reports compromises of ICS vendors and manufacturers in 2018 linked to XENOTIME (Reported [72]). On 19 November FireEye described phishing it detected at more than 20 clients on 14 November with technical overlaps to a suspected APT29 campaign of 9 November 2016; ATT&CK records it as campaign C0021 against public sector, NGO, education, oil and gas, chemical and hospitality targets (Confirmed [50][116]).

## Part 3: North Korea (summary; home: [North Korea-attributed actors](/case-studies/THREAT_ACTORS_NORTH_KOREA.md))

**HIDDEN COBRA alerts.** HIDDEN COBRA is the US Government's name for North Korean government cyber activity. TA18-149A of 29 May describes Joanap, a two-stage RAT, and Brambul, an SMB worm that brute-forces logins on ports 139 and 445 with hard-coded credential lists; trusted third parties report both in use since at least 2009, and the alert identifies 87 compromised Joanap nodes (Confirmed [24]). Neither is an ATT&CK software object in the library's data (Confirmed [118][119]).

**Park Jin Hyok.** On 6 September DOJ unsealed a complaint, filed 8 June, against Park Jin Hyok, alleged to belong to the team the private sector calls the Lazarus Group and to work for the front company Chosun Expo Joint Venture (Confirmed [36]). The conduct alleged includes the Sony Pictures attack (2014), the $81 million Bangladesh Bank theft (2016), WannaCry 2.0 (2017), bank intrusions from 2015 to 2018 attempting at least $1 billion, and 2016 to 2017 recruiter-lure spearphishing of US defense contractors including Lockheed Martin, which was unsuccessful (Confirmed, allegations [36]). The Bangladesh Bank theft and WannaCry are recorded in their own years in [the 2016 chronicle](/case-studies/CHRONICLE_2016.md) and [the 2017 chronicle](/case-studies/CHRONICLE_2017.md). OFAC designated Park and the company under E.O. 13722 the same day (Confirmed [37]). ATT&CK ids: G0032 Lazarus Group, S0366 WannaCry.

**FASTCash.** TA18-275A of 2 October describes compromised bank payment switch servers running unsupported AIX (AIX itself was not shown to be exploited) that approved fraudulent requests, active since at least late 2016 against banks in Africa and Asia, with simultaneous ATM withdrawals in over 30 countries in one 2017 incident and 23 countries in one 2018 incident; a trusted partner estimates tens of millions of dollars stolen (Confirmed [40]). The initial vector is unknown and spearphishing is surmised (Confirmed [40]).

**APT38.** FireEye named APT38 on 3 October: "We believe" it conducts financial crime for the North Korean regime, has attempted over $1.1 billion in heists and operated in more than 16 organizations in at least 13 countries since 2014, inserted fraudulent SWIFT transactions and altered transaction history from compromised victim systems without breaching SWIFT itself, and wiped disks and logs (Confirmed for FireEye's findings, Reported for the attribution [41]). ATT&CK G0082 says APT38 "has been attributed to the Reconnaissance General Bureau" and notes heavy overlap among North Korean group definitions, including Lazarus Group (Confirmed [114]). ATT&CK's G0082 rows citing FireEye's report are ATT&CK's mapping of a vendor report (Confirmed [114]).

**Operation Sharpshooter.** ATT&CK campaign C0013 (September 2017 to March 2019) targeted nuclear, defense, government, energy and financial companies and is linked to Lazarus Group by similarities, with no confidence level stated; McAfee's December 2018 report behind it returned 403 (Confirmed for the ATT&CK record [117][119]).

## Part 4: Iran (summary; home: [Iran-attributed actors](/case-studies/THREAT_ACTORS_IRAN.md))

**The Mabna Institute.** On 23 March DOJ charged nine Iranians tied to the Mabna Institute, which it says acted on behalf of the IRGC since 2013. The alleged victims are 144 US universities and 176 universities in 21 other countries, 47 companies, the US Department of Labor, FERC, the states of Hawaii and Indiana, the UN and UNICEF; over 31 TB was stolen, and over 100,000 professor accounts were targeted, about 8,000 compromised through spearphishing (Confirmed, allegations [13]). OFAC designated the institute and the nine the same day (Confirmed [13]). TA18-086A of 27 March ties password spraying against SSO, federated cloud and email applications, followed by Global Address List download, RDP lateral movement and FTP-tool exfiltration, to the same indictment (which the alert dates to February 2018) (Confirmed [77]). ATT&CK G0122 Silent Librarian's members are "known to have been affiliated with the Iran-based Mabna Institute" (Confirmed [113]).

**SamSam.** On 28 November a Newark grand-jury indictment charged Faramarz Shahi Savandi and Mohammad Mehdi Shah Mansouri with a 34-month scheme from December 2015 (six counts). It names over 200 victims, including the City of Atlanta, the City of Newark, the Port of San Diego, the Colorado DOT, the University of Calgary and six health care entities (Hollywood Presbyterian, Kansas Heart Hospital, LabCorp, MedStar Health, Nebraska Orthopedic Hospital and Allscripts), and alleges over $6 million in ransom collected and over $30 million in losses, with the most recent attack on 25 September 2018 (Confirmed, allegations [54]). The ransom was exchanged from bitcoin into rial through Iran-based exchangers; OFAC designated Ali Khorashadizadeh and Mohammad Ghorbaniyan and published two bitcoin addresses with over 7,000 transactions, the first time OFAC publicly attributed digital currency addresses to designated people (Confirmed [55]). AA18-337A of 3 December describes access through the JexBoss kit against JBoss in early 2016 and, from mid-2016, RDP access through brute force or stolen credentials, some bought on darknet markets, with networks infected within hours of a purchase (Confirmed [57]). ATT&CK lists SamSam as S0370 (Confirmed [111]).

## Part 5: China (summary; home: [China-attributed actors](/case-studies/THREAT_ACTORS_CHINA.md))

**APT10 and Cloud Hopper.** On 20 December DOJ unsealed an indictment of Zhu Hua and Zhang Shilong, alleged APT10 members at Huaying Haitai acting with the MSS Tianjin State Security Bureau, for intrusions from about 2006 to 2018 (Confirmed, allegations [58]). It describes an MSP Theft Campaign from 2014 reaching clients in at least 12 countries, a Technology Theft Campaign against more than 45 technology companies, and theft of data on more than 100,000 US Navy personnel, with malware named like OS files, stolen MSP administrator credentials used to move into client networks, and encrypted archives staged on other compromised hosts (Confirmed [58]). The same day the UK and its allies attributed APT 10 to China's MSS; the NCSC assesses "with the highest level of probability" that APT 10 ran the Cloud Hopper campaign against MSPs since at least 2016 and judges it "highly likely" APT 10 has an enduring relationship with the MSS (Confirmed [59]). Earlier, on 3 October, TA18-276B had warned of APT actors targeting MSPs since May 2016 with legitimate MSP credentials, PowerSploit, netsh, Robocopy and PuTTY SCP, naming no group (Confirmed [42]). ATT&CK id: G0045 menuPass (alias APT10).

**The Jiangsu MSS case.** On 30 October DOJ charged Jiangsu MSS officers Zha Rong and Chai Meng, with recruited hackers and insiders, for intrusions from January 2010 to May 2015 targeting turbofan engine technology at a French aerospace manufacturer and US aerospace firms (Confirmed, allegations [49]). No ATT&CK group id is tied to the case here.

**Thrip and Whitefly.** Symantec reported on 19 June that Thrip, first spotted through a January 2018 alert at a Southeast Asian telecom, targets satellite communications, geospatial imaging and defense in the US and Southeast Asia, and traced the attacks to three computers in China (Confirmed [26]). In March 2019 Symantec attributed the July 2018 attack on SingHealth, Singapore's largest public health organization, with a reported 1.5 million patient records stolen, to Whitefly, active since at least 2017 and using the Vcrodat loader through search-order hijacking (Confirmed for Symantec's findings [30]). ATT&CK G0107 links Whitefly to SingHealth (Confirmed [30][119]).

**The "Big Hack" story.** Bloomberg Businessweek's 4 October story claimed malicious chips in Supermicro hardware; it was not opened (403), and the claim is Reported only. Apple says it never found malicious chips or hardware manipulations in any server, and AWS calls the claims about Elemental and AWS China systems untrue and says it never found modified hardware or malicious chips (Confirmed [43][44]).

## Part 6: ransomware, fraud and crime

**SamSam set the pattern.** SamSam's operators entered over RDP and encrypted whole networks, and the indictment's victim list runs from hospitals to a port authority (Confirmed [57][54]). LabCorp's 8-K of 16 July describes suspicious activity detected on 14 July, systems taken offline and test processing briefly disrupted, with no evidence of data transfer; the indictment later lists LabCorp as a victim (Confirmed [31][54]).

**Ryuk appeared.** Check Point reported on 20 August that Ryuk had been used in targeted attacks over the prior two weeks, with ransoms of 15 to 50 BTC, an estimated take over $640,000 and code closely resembling HERMES; it framed a HERMES-operator or North Korea link only as a possibility (Reported [63]). The [2019 chronicle](/case-studies/CHRONICLE_2019.md) carries Ryuk's later record, and [the ransomware ecosystem study](/case-studies/RANSOMWARE_ECOSYSTEM.md) places it in the 2019 to 2026 record. ATT&CK id: S0446.

**GandCrab could be undone.** No More Ransom lists a Bitdefender decryptor for GandCrab versions 1, 4 and 5 up to 5.2; the decryptor's release date was not checked (Confirmed [64]).

**Emotet was the delivery layer.** TA18-201A calls Emotet among the most costly and destructive malware for SLTT governments, up to $1 million per incident to remediate, spread by malspam with five spreader modules, including a credential enumerator that brute-forces accounts and writes to SMB shares (Confirmed [32]). ATT&CK id: S0367.

**What the numbers say.** The FBI's IC3 recorded 351,937 complaints and losses over $2.7 billion in 2018; business email compromise accounted for 20,373 complaints and $1,297,803,489; ransomware for 1,493 complaints and $3,621,857 of adjusted losses; extortion for 51,146 complaints, up 242 percent on 2017, and over $83 million (Confirmed [65]). IC3 footnotes that its ransomware figure excludes lost business, time, wages, files, equipment and remediation, and counts only what victims report (Confirmed [65]). The losses DOJ attributes to SamSam alone, over $30 million from 2015 to 2018, exceed IC3's all-complaint ransomware figure for 2018 by a factor of about eight, so IC3 is a floor (Inferred arithmetic [54][65]).

**Card fraud groups.** On 7 February DOJ unsealed the Infraud indictment (Part 1) [4]. On 1 August it announced three FIN7 members in custody, Dmytro Fedorov, Fedir Hladyr and Andrii Kolpakov, arrested in Dresden, Bielsko-Biala and Lepe; it says FIN7, also called the Carbanak Group and Navigator Group, used a front company called Combi Security and reached victims with crafted emails backed by phone calls followed by adapted Carbanak malware (Confirmed, allegations [33]). ATT&CK keeps FIN7 (G0046) separate from Carbanak (G0008), and maps S0030 Carbanak as software (Confirmed [119]). Europol announced the arrest in Alicante of the leader of the gang behind the Carbanak and Cobalt attacks on over 100 financial institutions in 40 countries, about EUR 1 billion (Confirmed from the summary [66]).

**Takedowns.** On 24 April Dutch Police and the UK NCA, with Europol and about a dozen agencies, arrested the administrators of webstresser.org, a DDoS-for-hire marketplace selling attacks from EUR 15 a month (Confirmed from the summary [67]). On 27 November EDNY unsealed a 13-count indictment of eight defendants in the Methbot scheme (September 2014 to December 2016, over $7 million) and the 3ve scheme (December 2015 to October 2018, over 1.7 million infected computers, over $29 million), with arrests in Malaysia, Bulgaria and Estonia, seizure warrants for 31 domains and search warrants for 89 servers; the FBI sinkholed 23 domains tied to the Kovter botnet (Confirmed [52]). Google says 3ve at its peak controlled over 1 million IPs from residential malware infections and corporate IP space and generated billions of fraudulent ad bid requests, and credits White Ops (Confirmed [53]).

## Part 7: the memcached DDoS

Cloudflare described the memcached amplification vector on 27 February: memcached servers left open on UDP port 11211 reflect small requests as large responses, and Cloudflare saw 260 Gbps of inbound memcached traffic at peak (Confirmed [10]). The next day GitHub was fully unavailable from 17:21 to 17:26 UTC and intermittently until 17:30 under a DDoS from over a thousand ASNs that peaked at 1.35 Tbps and 126.9 million packets per second, with amplification up to 51,000 times; GitHub moved traffic to Akamai and published its report on 1 March (Confirmed [9]). The control is on the reflector's side: do not expose UDP services that answer unauthenticated requests with large replies (Inferred from [10]).

## Part 8: the data record

### Marriott and Starwood

Marriott's 8-K exhibit of 30 November says an internal security tool alerted on 8 September 2018 to an attempt to access the Starwood guest reservation database, that there had been unauthorized access to the Starwood network since 2014, and that the database held about 500 million guests, about 327 million with passport numbers and other details (Confirmed [56]). Card numbers were encrypted with AES-128, but Marriott could not rule out that both components needed to decrypt them were taken (Confirmed [56]). Its newsroom release adds that Marriott decrypted the data on 19 November and found it came from the Starwood database (Confirmed [70]). These are first-day figures; no later revision was opened, so this study gives only the 30 November numbers (Inferred [56]).

### Facebook and Google+

On 4 April Facebook said the information of up to 87 million people, mostly in the US, may have been improperly shared with Cambridge Analytica, and disabled phone and email search after malicious actors had abused it to scrape public profiles; this was data misuse, not an intrusion (Confirmed [17]). On 25 September its engineers found that attackers had exploited three interacting bugs in View As, introduced with a July 2017 change to the video uploader, to steal access tokens and take over accounts; Facebook reset tokens for almost 50 million affected accounts plus 40 million as a precaution and disabled View As (Confirmed [39]). On 12 October it revised the count: about 30 million people actually had tokens stolen (Confirmed [75]).

Google disclosed on 8 October a Google+ People API bug, found and patched in March, that potentially exposed non-public profile fields of up to 500,000 accounts to up to 438 apps, found no evidence of misuse, and announced the shutdown of consumer Google+ (Confirmed [45]). On 10 December it said a November API bug affected about 52.5 million users for six days and that no third party compromised its systems (Confirmed [76]).

### The rest of the year's disclosures

| Date | Organization | What the primary record says | Grade | Sources |
|---|---|---|---|---|
| 2018-03-29 | Under Armour (MyFitnessPal) | Data acquired in late February; about 150 million accounts; usernames, emails and hashed passwords, most bcrypt; no payment data | Confirmed | [14] |
| 2018-04-24 | Altaba (formerly Yahoo) | SEC: failure to disclose the December 2014 breach of hundreds of millions of accounts; $35 million penalty | Confirmed | [20] |
| 2018-06-04 | MyHeritage | Email addresses and hashed passwords of 92,283,889 users who signed up through 26 Oct 2017 found on a private outside server | Confirmed | [25] |
| 2018-06-23 | Ticketmaster UK | Malicious software on an Inbenta-hosted customer-support product; under 5 percent of global customers; North America not affected | Confirmed | [27] |
| 2018-07-04 | Timehop | A cloud credential with no MFA compromised; about 21 million users' names, emails, dates of birth, some phone numbers and social media access tokens taken | Confirmed | [28] |
| 2018-09-26 | Uber | Record $148 million settlement with all 50 states and DC over concealing the November 2016 breach of 57 million riders and drivers, after which the hackers demanded six figures | Confirmed | [38] |
| 2018-10-24 | Cathay Pacific | Data of up to 9.4 million passengers, including passport and identity card numbers, plus 403 expired card numbers and 27 card numbers without CVV | Confirmed | [48] |

## Part 9: supply chain and trusted access

The supply-chain record of 2018 is mostly about trust in people and providers rather than signed updates. TA18-074A's staging targets were trusted third-party suppliers with less secure networks (Confirmed [11]). TA18-276B and the APT10 indictment describe MSP credentials used to reach customers (Confirmed [42][58]).

**event-stream (summary; home: [npm supply-chain attacks](/case-studies/NPM_SUPPLY_CHAIN_ATTACKS.md)).** npm reports that a new maintainer added the malicious flatmap-stream 0.1.1 as a dependency of event-stream 3.3.6 on 9 September, targeting the Copay build; npm was notified on 26 November, removed both packages and took ownership of event-stream (Confirmed [73]).

**Gentoo.** Gentoo's incident report says an attacker took over an admin account of the Gentoo GitHub organization through a guessable password pattern on 28 June, removed developer access and altered content; GitHub froze the organization, and Gentoo-hosted infrastructure was unaffected (Confirmed [74]).

**Ticketmaster and Inbenta.** Ticketmaster UK found malicious software on a customer-support product hosted by its third-party supplier Inbenta Technologies and disabled it (Confirmed [27]). Reading this as a compromise of a supplier-hosted component running on the company's own site is this study's view (Inferred).

**The Big Hack.** Part 5 covers the hardware-implant claim that the companies named denied (Confirmed for the denials [43][44]).

## Part 10: industrial systems and critical infrastructure

Four threads from 2018 reach control systems. TA18-074A's actors used watering holes on ICS-related sites and collected SCADA files, VNC profiles and HMI screenshots from ICS-related hosts (Confirmed [11]). VPNFilter's stage 3 plugin monitored Modbus traffic (Confirmed [22]); ATT&CK maps S1010 to ICS T0830 Adversary-in-the-Middle and T0842 Network Sniffing (Confirmed [108]). ESET disclosed GreyEnergy on 17 October as a successor to BlackEnergy, used for three years against energy companies and other high-value targets in Ukraine and Poland, mainly for espionage (Confirmed [47]). FireEye's TRITON attribution and Dragos's report on XENOTIME vendor compromises are vendor assessments (Reported [71][72]).

TSMC is the counterexample. Its 5 August release reports a computer virus outbreak on the evening of 3 August that hit computer systems and fab tools in Taiwan, blames misoperation during software installation for a new tool, and estimates the Q3 revenue impact at about 3 percent; it does not name WannaCry and does not describe an attack (Confirmed [34]). Listing it as an attack misstates the record (Inferred).

## Part 11: vulnerabilities and exploitation

### Spectre and Meltdown

Project Zero disclosed variant 1 (CVE-2017-5753), variant 2 (CVE-2017-5715) and variant 3 (CVE-2017-5754, Meltdown), reported to Intel, AMD and ARM on 1 June 2017 (Confirmed [1]). NVD published them on 4 January 2018, and the researchers' site says they do not know whether they were abused (Confirmed [2]). AWS's bulletin AWS-2018-013 covers all three, and EC2 Amazon Linux instances launched on or after 13 January include the patched kernel (Confirmed [3]). None of the three (CVE-2017-5753, CVE-2017-5715, CVE-2017-5754) is in KEV (Confirmed [86]). They are a class of hardware design flaw, not a 2018 intrusion (Inferred).

### The CVEs that defined the year

| CVE | Product and flaw | Published (NVD or vendor) | CWE (source) | KEV | Sources |
|---|---|---|---|---|---|
| CVE-2018-0802 | Microsoft Office Equation Editor RCE | 2018-01-10 | CWE-787 (NVD) | Yes, known ransomware use | [103][86] |
| CVE-2018-0101 | Cisco ASA SSL VPN double free | 2018-01-29 | CWE-415 (NVD) | not stated | [87] |
| CVE-2018-4878 | Adobe Flash Player use-after-free | 2018-02-06 | CWE-416 (NVD); CVSS 7.8 | Yes, since 2021-11-03, known ransomware use | [88][86] |
| CVE-2018-6789 | Exim base64d buffer overflow | 2018-02-08 | CWE-120 (NVD) | Yes, known ransomware use | [104][86] |
| CVE-2018-0171 | Cisco IOS and IOS XE Smart Install buffer overflow | 2018-03-28 | CWE-20 (Cisco), CWE-787 (NVD); CVSS 9.8 | Yes, since 2021-11-03, ransomware use Unknown | [90][91][86] |
| CVE-2018-7600 | Drupal core RCE (Drupalgeddon2) | 2018-03-28 (Drupal), 2018-03-29 (NVD) | CWE-20 (NVD); CVSS 9.8 | Yes, since 2021-11-03, known ransomware use | [15][89][86] |
| CVE-2018-2628 | Oracle WebLogic deserialization | 2018-04-19 | CWE-502 (NVD) | Yes | [92] |
| CVE-2018-10561 | Dasan GPON router authentication bypass | 2018-05-04 | CWE-287 (NVD) | Yes; sibling CVE-2018-10562 with known ransomware use | [93] |
| CVE-2018-8174 | Windows VBScript engine RCE | 2018-05-09 | CWE-787 (NVD); CVSS 7.5 | Yes, since 2022-02-15, known ransomware use | [94][86] |
| CVE-2018-8120 | Win32k elevation of privilege | 2018-05-09 | CWE-404 (NVD) | Yes, known ransomware use | [94][86] |
| CVE-2018-0296 | Cisco ASA web interface path traversal and DoS | 2018-06-07 | CWE-20, CWE-22 (NVD) | Yes | [95] |
| CVE-2018-7602 | Drupal core follow-on RCE | 2018-07-19 | NVD-CWE-noinfo (NVD), CWE-94 (CNA) | Yes, since 2022-04-13, known ransomware use | [123][86] |
| CVE-2018-14847 | MikroTik RouterOS directory traversal | 2018-08-02 | CWE-22 (NVD) | Yes | [96] |
| CVE-2018-11776 | Apache Struts namespace RCE | 2018-08-22 | NVD-CWE-noinfo (NVD), CWE-20 (KEV); CVSS 8.1 | Yes, since 2021-11-03 | [98][86] |
| CVE-2018-8453 | Win32k elevation of privilege (October zero-day) | 2018-10 | not stated here | Yes, known ransomware use | [97][86] |
| CVE-2018-15961 | Adobe ColdFusion unrestricted file upload | 2018-09-25 | CWE-434 (NVD) | Yes | [99] |
| CVE-2018-10933 | libssh server-side authentication bypass | 2018-10-17 | CWE-287 (NVD) | No | [100][86] |
| CVE-2018-1002105 | Kubernetes API server proxied-upgrade privilege escalation | 2018-12-05 | not stated here | No | [101][86] |
| CVE-2018-20062 | ThinkPHP and NoneCms RCE | 2018-12-11 | not stated here | Yes | [102] |

The Microsoft zero-days of the second half of the year that KEV now carries are CVE-2018-8373 (scripting engine, August), CVE-2018-8440 (ALPC, NVD 13 September), CVE-2018-8453 (Win32k, October), CVE-2018-8589 (Win32k, November), CVE-2018-8611 (kernel, December) and CVE-2018-8653 (scripting engine, NVD 20 December); KEV marks 8440 and 8453 with known ransomware use (Confirmed [97][86]).

Cisco's advisory for CVE-2018-0171 was later updated to record in-the-wild exploitation attempts (a November 2021 note) and continued exploitation (20 August 2025) (Confirmed [90]). Smart Install shows up twice in 2018: as a protocol abused without any vulnerability (Talos, TA18-106A) and as this memory-safety CVE (Confirmed [18][19][90]).

### 2018 CVEs in KEV

CISA's KEV catalog (version 2026.11.10, 1,779 entries) holds 89 CVE-2018 entries, 33 marked known ransomware campaign use; the top vendors are Cisco (18), Microsoft (16), Adobe (6), GIGABYTE (4) and Fortinet (4) (Confirmed [86]). None was added in 2018, because KEV began on 3 November 2021: 18 were added in 2021 (17 on the first day), 62 in 2022, 1 in 2023, 3 in 2024, 4 in 2025 and 1 in 2026, CVE-2018-14634 in the Linux kernel on 26 January 2026 (Confirmed [86]). The most frequent CWE ids are CWE-20 (14), none listed (10), CWE-78 (9), CWE-787 (9), CWE-404 (6), CWE-119 (6), CWE-502 (5), CWE-22 (5) and CWE-399 (5) (Confirmed [86]). KEV's dates for these entries are catalog history, not exploitation dates (Inferred).

A CVE-2018 id is not a 2018 event. NVD published CVE-2018-13379 (FortiOS SSL VPN path traversal, CWE-22) on 4 June 2019, CVE-2018-15982 (Flash) on 18 January 2019 and CVE-2018-20250 (WinRAR ACE) on 5 February 2019; this chronicle dates by advisory, so those belong to [the 2019 record](/case-studies/CHRONICLE_2019.md) (Confirmed for the dates [105]; the rule Inferred).

## Part 12: the government record

### Attribution, charges and sanctions

| Date | Action | Actor named | Hedging in the source | Sources |
|---|---|---|---|---|
| 2018-02-15 | UK and US attribute NotPetya | Russian military | UK: "almost certainly"; US: unhedged | [7][8] |
| 2018-03-15 | TA18-074A | Russian government cyber actors | Flat; Dragonfly only through Symantec's citation | [11] |
| 2018-03-15 | OFAC designations (CAATSA, E.O. 13694) | FSB, GRU, IRA and others | Sanctions finding | [12] |
| 2018-03-23 | Mabna indictment and designations | Mabna Institute, for the IRGC | Allegation | [13] |
| 2018-04-16 | TA18-106A (US and UK) | Russian state-sponsored actors | "assesses"; FBI "high confidence" on man-in-the-middle | [19] |
| 2018-05-23 | VPNFilter domain seizure | Sofacy Group (APT28) | Court filing | [23] |
| 2018-05-29 | TA18-149A | HIDDEN COBRA (North Korean government) | Flat | [24] |
| 2018-06-11 | OFAC designations | Five entities supporting the FSB | Sanctions finding | [61] |
| 2018-07-13 | Indictment of 12 GRU officers | GRU Units 26165 and 74455 | Allegation | [29] |
| 2018-08 | Microsoft takes six domains | Strontium (APT28) | Court order | [35] |
| 2018-09-06 | Park Jin Hyok complaint and designation | Lazarus Group, Chosun Expo Joint Venture | Allegation | [36][37] |
| 2018-10-02 | TA18-275A | HIDDEN COBRA | Flat | [40] |
| 2018-10-03 | FireEye names APT38 | North Korean regime | "We believe" (vendor) | [41] |
| 2018-10-04 | Indictment of seven GRU officers; UK exposure after the Dutch statement | GRU | Allegation; UK "almost certainly" | [21][16] |
| 2018-10-23 | FireEye on TRITON | CNIIHM | "high confidence" (vendor) | [71] |
| 2018-10-30 | Jiangsu MSS indictment | Jiangsu State Security Department officers | Allegation | [49] |
| 2018-11-28 | SamSam indictment and designations | Two Iranian men; two Iran-based exchangers | Allegation; sanctions finding | [54][55] |
| 2018-12-19 | OFAC designations | Nine GRU officers; two for WADA and the OPCW | Sanctions finding | [60] |
| 2018-12-20 | APT10 indictment; UK and allies' statement | APT10 for the MSS Tianjin bureau | Allegation; "highest level of probability" | [58][59] |

Read together, these show 2018 as the year Western governments formally named state operators in volume: attributions in February, sanctions in March, June, September, November and December, indictments of GRU, IRGC-linked, North Korean and MSS-linked operators, the first joint US and UK router advisory, and a coordinated exposure of the GRU with the Netherlands (Inferred [7][12][61][37][55][60][29][21][13][36][49][58][19][16]).

### Rules and laws

| Date | Instrument | What it does | Sources |
|---|---|---|---|
| 2018-03-23 | Public Law 115-141 (Consolidated Appropriations Act, 2018) | Carries the CLOUD Act; the CLOUD Act text was not checked on the page opened | [78] |
| 2018-04-16 | NIST Cybersecurity Framework 1.1 | Version 1.1 released | [79] |
| 2018-06-28 | California AB-375, Consumer Privacy Act of 2018 (Chapter 55) | Consumer rights from 1 Jan 2020 | [80] |
| 2018-08-31 | Singapore Cybersecurity Act 2018 (Act 9 of 2018) | Provides for designating critical information infrastructure | [81] |
| 2018-09-12 | Executive Order 13848 (83 FR 46843) | Sanctions in the event of foreign interference in a US election | [82] |
| 2018-09-20 | National Cyber Strategy | First fully articulated US cyber strategy since 2003 | [83] |
| 2018-11-16 | Public Law 115-278, CISA Act of 2018 (H.R. 3359) | Authorizes the Cybersecurity and Infrastructure Security Agency | [84] |
| 2018-12 | Australia's Telecommunications and Other Legislation Amendment (Assistance and Access) Act 2018, C2018A00148 | Registered on the Federal Register of Legislation; assent date not checked | [85] |

## Part 13: the defender view

**Network devices needed owners.** TA18-106A's mitigations are a device-hygiene list: no plaintext management protocols from the internet and no internet access to management interfaces; Telnet and SNMPv1/v2c disabled in favor of SSH and SNMPv3; default passwords changed, unique per device, with two-factor where possible; Smart Install disabled before deployment; outbound TFTP blocked; firmware integrity verified; unsupported equipment retired; and vendors shipping legacy and unauthenticated services disabled by default (Confirmed [19]). Talos's VPNFilter advice adds factory resets, reboots, ISP-side reboots and patching (Confirmed [22]). The library's D3FEND data has no countermeasure for T1602.002 Network Device Configuration Dump, and only one each for T1040 Network Sniffing (DNS Traffic Analysis) and T1561.001 Disk Content Wipe (Disk Partitioning) (Confirmed [121]); the controls for the edge come from the advisory, not from a D3FEND row.

**Credentials needed a second factor.** TA18-074A says the actors used compromised credentials to reach networks where multi-factor authentication was not used, and asks for two-factor authentication for all authentication, especially external interfaces, plus blocking SMB and WebDAV at the boundary, segmenting control systems, PowerShell 5 logging, application directory allowlisting, blocking RDP from untrusted external addresses, one-year SIEM retention and fewer domain and enterprise admin accounts (Confirmed [11]). TA18-086A adds NIST-aligned password policy and review of helpdesk reset procedures (Confirmed [77]). The library pairs T1110.003 Password Spraying with ATT&CK mitigations M1027 Password Policies, M1032 Multi-factor Authentication and M1036 Account Use Policies, and with D3FEND [Multi-factor Authentication](/mitre/d3fend/multi-factor-authentication.md) and [Strong Password Policy](/mitre/d3fend/strong-password-policy.md) among others (Confirmed [121]).

**Remote access was the ransomware door.** AA18-337A asks for RDP to be audited and disabled where it is not needed, no open 3389 on public cloud VMs, a VPN in front of RDP, 90 days of RDP login logs, strong passwords with lockout, two-factor and a good backup strategy (Confirmed [57]). The library maps T1133 External Remote Services to M1021, M1030, M1032, M1035 and M1042, and T1021.001 Remote Desktop Protocol to M1018, M1026, M1028, M1030, M1032, M1035, M1042 and M1047; its only D3FEND pairing for T1133 is [Session Termination](/mitre/d3fend/session-termination.md) (Confirmed [121]).

**SMB carried the worms.** TA18-201A asks for Group Policy rules that block client-to-client SMB, email gateway filtering, DMARC, external-mail banners, least privilege, no privileged logons to infected hosts during remediation and checks of Outlook auto-forward rules (Confirmed [32]). TA18-149A's Brambul spread the same way (Confirmed [24]). The library has no D3FEND mapping for T1021.002 SMB/Windows Admin Shares (Confirmed [121]).

**Providers needed limits.** TA18-276B recommends a dedicated certificate-authenticated VPN for MSP access terminated in a DMZ, MSP accounts kept out of Enterprise and Domain Admin groups, scoped and time-limited, plus segmentation and outbound restrictions (Confirmed [42]). The library maps T1199 Trusted Relationship to M1018, M1030 and M1032 (Confirmed [121]).

**Payment systems needed baselines.** TA18-275A asks for isolated switch servers, mutual TLS on payment links, and baselines of software, logons and transaction patterns (Confirmed [40]).

**Public tools are the common case.** AA18-284A says initial compromises usually come from unpatched software or poor configuration and that even the most sophisticated groups use common public tools (Confirmed [46]).

**Recovery and logging decided the outcome.** Olympic Destroyer and SamSam both went after recovery (Confirmed [5][57]); the library maps T1490 Inhibit System Recovery to M1018, M1028, M1038 and M1053 and T1486 Data Encrypted for Impact to M1040 and M1053 (Confirmed [121]). The logging asks (PowerShell 5 logging and one-year retention in TA18-074A, 90-day RDP logs in AA18-337A) only help if they were on beforehand (Confirmed [11][57]; the reading Inferred).

**The same list recurs.** Read together, TA18-074A, TA18-086A, TA18-106A, TA18-201A, TA18-276B and AA18-337A ask for one set of controls: multi-factor authentication on every external interface, reduced remote-access exposure, network devices treated as a first-class asset class, limits on MSP and supplier trust, SMB and credential lateral-movement controls, recoverable backups, and logging enabled before the incident (Inferred [11][77][19][32][42][57]).

## Part 14: MITRE mappings

Every id below was checked against the library's data files (`data/attack/technique_profiles.jsonl`, `data/attack/ics/technique_profiles.jsonl`, `groups.jsonl`, `software.jsonl`, `campaigns.jsonl`, `campaign_profiles.jsonl`, `software_to_technique.jsonl`, `group_to_technique.jsonl`, `data/attack/ics/group_to_technique.jsonl`, `technique_to_d3fend.jsonl`, `mitigation_to_technique.jsonl`, `superseded_by.jsonl`, `data/weaknesses/cwe.jsonl` and `capec.jsonl`) and the generated pages under `mitre/` on 11 November 2026 [119][120][121][122], with the objects that carry 2018 procedures opened on attack.mitre.org [106][107][108][109][110][111][112][113][114][115][116][117][118]. Names and tactics are those of ATT&CK v20.0, the library's basis; the live G0035 page showed content v20.1 [106]. Revoked ids are mapped through `superseded_by.jsonl`: Clear Windows Event Logs (T1070.001) is now T1685.005, and Disable or Modify System Firewall (T1562.004) is now T1686 (Confirmed [119]).

The Basis column says how strong each tie is: **Listed** means an ATT&CK object (group, software or campaign, as the library's data records it) prints the technique with a procedure that cites the 2018 record, or the cited source prints the id; **Described** means the source describes the behavior and the mapping is this study's; **Reported** means only a Reported source supports the behavior; **Inferred** marks a mapping of described behavior that this study makes with less direct support (Timehop, Facebook, Gentoo, the router campaign's discovery step).

Three cautions apply. The 41 G0035 rows cite TA18-074A, so they describe a campaign from March 2016 that the alert published in March 2018 (Confirmed [106]). The G0007 rows cite the July and October 2018 indictments, whose conduct runs from 2014 to 2018 (Confirmed [115]). The G0034 rows cite the UK NCSC statement of October 2020 on the Olympic and Paralympic Games (Confirmed [109]). Several advisories carry techniques that no ATT&CK object row cites: TA18-086A's password spraying, TA18-106A's man-in-the-middle, sniffing and brute force, AA18-337A's RDP access and encryption, TA18-276B's trusted relationship and TA18-275A's valid accounts are marked Described in the event column (Inferred [77][19][57][42][40]). ATT&CK's S0370 SamSam lists only five techniques, and AA18-337A is in its references but no technique row cites it, so the RDP initial access the advisory documents is absent from the software object (Confirmed [111]).

### ATT&CK Enterprise techniques

| Id | Name (ATT&CK v20.0) | Tactic(s) | Basis | Dated event or report | Sources |
|---|---|---|---|---|---|
| [`T1589.002`](/mitre/techniques/T1589-002.md) | Email Addresses | reconnaissance | Listed | G0122 rows citing the Mabna indictment (23 Mar 2018) | [113] |
| [`T1589.003`](/mitre/techniques/T1589-003.md) | Employee Names | reconnaissance | Listed | G0122 rows citing the Mabna indictment | [113] |
| [`T1591.002`](/mitre/techniques/T1591-002.md) | Business Relationships | reconnaissance | Listed | G0034 rows citing the UK NCSC statement of 19 Oct 2020 on attacks against the Olympic and Paralympic Games | [109] |
| [`T1594`](/mitre/techniques/T1594.md) | Search Victim-Owned Websites | reconnaissance | Listed | G0122 rows citing the Mabna indictment | [113] |
| [`T1595`](/mitre/techniques/T1595.md) | Active Scanning | reconnaissance | Inferred | Russian router and switch campaign: devices found through exposed legacy services (TA18-106A, 16 Apr 2018); the advisory does not name scanning | [19] |
| [`T1598.002`](/mitre/techniques/T1598-002.md) | Spearphishing Attachment | reconnaissance | Listed | G0035 rows citing TA18-074A (15 Mar 2018) | [106][11] |
| [`T1598.003`](/mitre/techniques/T1598-003.md) | Spearphishing Link | reconnaissance | Listed | G0035 (TA18-074A); G0122 (Mabna indictment); G0007 rows citing the July and October 2018 GRU indictments | [106][113][115] |
| [`T1583.001`](/mitre/techniques/T1583-001.md) | Domains | resource-development | Listed | G0122 (Mabna indictment); G0045 (APT10 indictment, Dec 2018); G0007 (October 2018 GRU indictment); six look-alike domains seized by Microsoft, Aug 2018 (Described) | [113][112][115][35] |
| [`T1583.006`](/mitre/techniques/T1583-006.md) | Web Services | resource-development | Listed | C0013 Operation Sharpshooter (Sep 2017 to Mar 2019) | [117] |
| [`T1584.001`](/mitre/techniques/T1584-001.md) | Domains | resource-development | Listed | C0021, the November 2018 spearphishing campaign | [116][119] |
| [`T1584.004`](/mitre/techniques/T1584-004.md) | Server | resource-development | Listed | C0013 | [117] |
| [`T1585.002`](/mitre/techniques/T1585-002.md) | Email Accounts | resource-development | Listed | G0122 rows citing the Mabna indictment | [113] |
| [`T1587.001`](/mitre/techniques/T1587-001.md) | Malware | resource-development | Listed | C0013; G0034 rows citing the NCSC Olympic statement (2020) | [117][109] |
| [`T1588.002`](/mitre/techniques/T1588-002.md) | Tool | resource-development | Listed | G0034 rows citing the NCSC Olympic statement; C0021; the five public tools of AA18-284A, 11 Oct 2018 (Described) | [109][116][119][46] |
| [`T1588.006`](/mitre/techniques/T1588-006.md) | Vulnerabilities | resource-development | Listed | G0034 rows citing the NCSC Olympic statement | [109] |
| [`T1608.001`](/mitre/techniques/T1608-001.md) | Upload Malware | resource-development | Listed | C0013; C0021 | [117][116] |
| [`T1078`](/mitre/techniques/T1078.md) | Valid Accounts | stealth, persistence, privilege-escalation, initial-access | Listed | G0035, G0045, G0122 and G0007 rows; legitimate-user masquerade on network devices (TA18-106A, Described); legitimate credentials on FASTCash switch servers (TA18-275A, Described) | [106][112][113][115][19][40] |
| [`T1078.004`](/mitre/techniques/T1078-004.md) | Cloud Accounts | stealth, persistence, privilege-escalation, initial-access | Inferred | Timehop: a credential to its cloud computing environment, with no multi-factor authentication, compromised (4 Jul 2018) | [28] |
| [`T1133`](/mitre/techniques/T1133.md) | External Remote Services | persistence, initial-access | Listed | VPN, RDP and OWA access with harvested credentials (G0035, TA18-074A); SamSam's internet-facing RDP from mid-2016 (AA18-337A, Described) | [106][11][57] |
| [`T1189`](/mitre/techniques/T1189.md) | Drive-by Compromise | initial-access | Listed | Watering holes on trade-publication and ICS-related sites (G0035, TA18-074A); G0082 rows citing FireEye's APT38 report (3 Oct 2018) | [106][11][114] |
| [`T1190`](/mitre/techniques/T1190.md) | Exploit Public-Facing Application | initial-access | Listed | G0007 rows citing the October 2018 GRU indictment; SamSam through JBoss with the JexBoss kit, early 2016 (AA18-337A, Described) | [115][57] |
| [`T1195.001`](/mitre/techniques/T1195-001.md) | Compromise Software Dependencies and Development Tools | initial-access | Described | A new maintainer adds the malicious flatmap-stream dependency to event-stream 3.3.6, 9 Sep 2018, aimed at the Copay build (npm) | [73] |
| [`T1199`](/mitre/techniques/T1199.md) | Trusted Relationship | initial-access | Listed | G0045 rows citing the APT10 indictment (MSP Theft Campaign); G0007 (July 2018 indictment); MSP credentials (TA18-276B, 3 Oct 2018, Described); staging targets (TA18-074A, Described) | [112][115][42][11] |
| [`T1566`](/mitre/techniques/T1566.md) | Phishing | initial-access | Described | GRU spearphishing of the UK FCO (Mar 2018) and of OPCW staff impersonating Swiss authorities (May 2018); spearphishing in the October 2018 GRU indictment | [16][21] |
| [`T1566.001`](/mitre/techniques/T1566-001.md) | Spearphishing Attachment | initial-access | Listed | Office attachments sent from compromised accounts (TA18-074A, Described; the library also maps T1566.001 to G0035); S0367 Emotet (TA18-201A, 20 Jul 2018); G0045 (APT10 indictment); G0007 (July 2018 indictment); FIN7 emails with attachments backed by phone calls (DOJ, 1 Aug 2018; Described) | [106][110][112][115][33] |
| [`T1566.002`](/mitre/techniques/T1566-002.md) | Spearphishing Link | initial-access | Listed | S0367 (TA18-201A); C0021 (Nov 2018) | [110][116] |
| [`T1669`](/mitre/techniques/T1669.md) | Wi-Fi Networks | initial-access | Described | GRU close-access Wi-Fi operation against OPCW networks in The Hague, April 2018 (DOJ indictment allegation) | [21] |
| [`T1047`](/mitre/techniques/T1047.md) | Windows Management Instrumentation | execution | Listed | S0365 Olympic Destroyer, 9 Feb 2018 (Talos describes WMI spreading) | [107][5] |
| [`T1053.005`](/mitre/techniques/T1053-005.md) | Scheduled Task | execution, persistence, privilege-escalation | Listed | G0035 (TA18-074A); S0367 (TA18-201A) | [106][110] |
| [`T1059`](/mitre/techniques/T1059.md) | Command and Scripting Interpreter | execution | Listed | G0035 rows citing TA18-074A | [106] |
| [`T1059.001`](/mitre/techniques/T1059-001.md) | PowerShell | execution | Listed | G0035 (TA18-074A); C0021 | [106][116] |
| [`T1059.003`](/mitre/techniques/T1059-003.md) | Windows Command Shell | execution | Listed | G0035 (TA18-074A); G0082 (FireEye, Oct 2018); S0370 SamSam | [106][114][111] |
| [`T1059.005`](/mitre/techniques/T1059-005.md) | Visual Basic | execution | Listed | C0013 | [117] |
| [`T1059.006`](/mitre/techniques/T1059-006.md) | Python | execution | Listed | G0035 rows citing TA18-074A | [106] |
| [`T1106`](/mitre/techniques/T1106.md) | Native API | execution | Listed | C0013 | [117] |
| [`T1204.001`](/mitre/techniques/T1204-001.md) | Malicious Link | execution | Listed | G0007 rows citing the October 2018 indictment; C0021 | [115][116] |
| [`T1204.002`](/mitre/techniques/T1204-002.md) | Malicious File | execution | Listed | C0013; G0045 rows citing the APT10 indictment | [117][112] |
| [`T1559.002`](/mitre/techniques/T1559-002.md) | Dynamic Data Exchange | execution | Listed | C0013 | [117] |
| [`T1569.002`](/mitre/techniques/T1569-002.md) | Service Execution | execution | Listed | S0365 Olympic Destroyer with PsExec; Thrip's PsExec install of Catchamas, Jan 2018 (Symantec, Described) | [107][26] |
| [`T1574.001`](/mitre/techniques/T1574-001.md) | DLL | stealth, execution | Described | Whitefly loads Vcrodat through search-order hijacking (Symantec, 6 Mar 2019, on the July 2018 SingHealth attack); the library maps T1574.001 to G0107 | [30][119] |
| [`T1098.007`](/mitre/techniques/T1098-007.md) | Additional Local or Domain Groups | persistence, privilege-escalation | Listed | G0035 rows citing TA18-074A | [106] |
| [`T1112`](/mitre/techniques/T1112.md) | Modify Registry | defense-impairment, persistence | Listed | G0035 (TA18-074A registry change to keep plaintext credentials in memory); G0082 | [106][11][114] |
| [`T1136.001`](/mitre/techniques/T1136-001.md) | Local Account | persistence | Listed | Local administrator accounts created in the Dragonfly campaign (G0035, TA18-074A) | [106][11] |
| [`T1505.003`](/mitre/techniques/T1505-003.md) | Web Shell | persistence | Listed | Web shells on public email and web servers (G0035, TA18-074A) | [106][11] |
| [`T1542.001`](/mitre/techniques/T1542-001.md) | System Firmware | stealth, persistence | Listed | LoJax writes to SPI flash and survives OS reinstall and disk replacement (ESET, 27 Sep 2018; S0397 in the library's data) | [62][119] |
| [`T1543.003`](/mitre/techniques/T1543-003.md) | Windows Service | persistence, privilege-escalation | Listed | S0367 (TA18-201A) | [110] |
| [`T1547.001`](/mitre/techniques/T1547-001.md) | Registry Run Keys / Startup Folder | persistence, privilege-escalation | Listed | G0035 (TA18-074A); S0367 (TA18-201A); C0013 | [106][110][117] |
| [`T1055`](/mitre/techniques/T1055.md) | Process Injection | stealth, privilege-escalation | Listed | C0013; FASTCash switch-server manipulation (TA18-275A, mapping Inferred) | [117][40] |
| [`T1055.001`](/mitre/techniques/T1055-001.md) | Dynamic-link Library Injection | stealth, privilege-escalation | Listed | S0367 (TA18-201A) | [110] |
| [`T1027.002`](/mitre/techniques/T1027-002.md) | Software Packing | stealth | Listed | G0082 rows citing FireEye's APT38 report | [114] |
| [`T1027.009`](/mitre/techniques/T1027-009.md) | Embedded Payloads | stealth | Listed | C0021 (library campaign data) | [119] |
| [`T1027.010`](/mitre/techniques/T1027-010.md) | Command Obfuscation | stealth | Listed | C0021 (library campaign data) | [119] |
| [`T1027.013`](/mitre/techniques/T1027-013.md) | Encrypted/Encoded File | stealth | Listed | S0370 SamSam | [111] |
| [`T1027.016`](/mitre/techniques/T1027-016.md) | Junk Code Insertion | stealth | Listed | S0370 SamSam | [111] |
| [`T1036.005`](/mitre/techniques/T1036-005.md) | Match Legitimate Resource Name or Location | stealth | Listed | G0045 rows citing the APT10 indictment (malware named as OS files); C0013 | [112][117] |
| [`T1036.010`](/mitre/techniques/T1036-010.md) | Masquerade Account Name | stealth | Listed | Local accounts disguised as backup accounts (G0035, TA18-074A) | [106][11] |
| [`T1070.004`](/mitre/techniques/T1070-004.md) | File Deletion | stealth | Listed | G0035, G0045, G0082 and G0007 rows; S0370; tools deleted (TA18-074A) | [106][112][114][115][111][11] |
| [`T1140`](/mitre/techniques/T1140.md) | Deobfuscate/Decode Files or Information | stealth | Listed | C0021 (library campaign data) | [119] |
| [`T1218.011`](/mitre/techniques/T1218-011.md) | Rundll32 | stealth | Listed | C0021 | [116] |
| [`T1564.002`](/mitre/techniques/T1564-002.md) | Hidden Users | stealth | Listed | G0035 rows citing TA18-074A | [106] |
| [`T1685.005`](/mitre/techniques/T1685-005.md) | Clear Windows Event Logs | defense-impairment | Listed | G0035 (TA18-074A log clearing); S0365 Olympic Destroyer; G0082; G0007 (July 2018 indictment) | [106][107][114][115] |
| [`T1686`](/mitre/techniques/T1686.md) | Disable or Modify System Firewall | defense-impairment | Listed | G0035 rows citing TA18-074A (host firewall disabled) | [106] |
| [`T1003`](/mitre/techniques/T1003.md) | OS Credential Dumping | credential-access | Listed | G0007 rows citing the July and October 2018 GRU indictments | [115] |
| [`T1003.001`](/mitre/techniques/T1003-001.md) | LSASS Memory | credential-access | Listed | S0365 (credentials from LSASS, Talos); G0007 (July 2018 indictment) | [107][5][115] |
| [`T1003.002`](/mitre/techniques/T1003-002.md) | Security Account Manager | credential-access | Listed | G0035 (TA18-074A) | [106] |
| [`T1003.003`](/mitre/techniques/T1003-003.md) | NTDS | credential-access | Listed | NTDS collection (G0035, TA18-074A) | [106][11] |
| [`T1003.004`](/mitre/techniques/T1003-004.md) | LSA Secrets | credential-access | Listed | G0035 (TA18-074A) | [106] |
| [`T1040`](/mitre/techniques/T1040.md) | Network Sniffing | credential-access, discovery | Listed | G0007 rows citing the October 2018 indictment; VPNFilter's stage 3 sniffer (Talos, Described) | [115][22] |
| [`T1056.001`](/mitre/techniques/T1056-001.md) | Keylogging | collection, credential-access | Listed | G0045 (APT10 indictment); G0082; G0007 (July 2018 indictment) | [112][114][115] |
| [`T1110`](/mitre/techniques/T1110.md) | Brute Force | credential-access | Described | Brute force and credential reuse against network devices (TA18-106A); SamSam RDP brute force (AA18-337A) | [19][57] |
| [`T1110.001`](/mitre/techniques/T1110-001.md) | Password Guessing | credential-access | Listed | S0367 (TA18-201A credential enumerator); Brambul's hard-coded credential lists against SMB (TA18-149A, Described); Gentoo's guessable password pattern, 28 Jun 2018 (Inferred) | [110][24][74] |
| [`T1110.002`](/mitre/techniques/T1110-002.md) | Password Cracking | credential-access | Listed | Hashes harvested by forced SMB authentication cracked (G0035, TA18-074A) | [106][11] |
| [`T1110.003`](/mitre/techniques/T1110-003.md) | Password Spraying | credential-access | Listed | G0122 rows citing the Mabna indictment; password spraying against SSO, cloud and email (TA18-086A, 27 Mar 2018, Described) | [113][77] |
| [`T1187`](/mitre/techniques/T1187.md) | Forced Authentication | credential-access | Listed | Office documents that fetch a remote resource over SMB (G0035, TA18-074A) | [106][11] |
| [`T1528`](/mitre/techniques/T1528.md) | Steal Application Access Token | credential-access | Inferred | Facebook View As: attackers stole access tokens, found 25 Sep 2018 and disclosed 28 Sep 2018 | [39][75] |
| [`T1552.001`](/mitre/techniques/T1552-001.md) | Credentials In Files | credential-access | Listed | S0367 (TA18-201A) | [110] |
| [`T1555.003`](/mitre/techniques/T1555-003.md) | Credentials from Web Browsers | credential-access | Listed | S0365 (credentials from browsers, Talos) | [107][5] |
| [`T1557`](/mitre/techniques/T1557.md) | Adversary-in-the-Middle | credential-access, collection | Described | Compromised routers used for man-in-the-middle (TA18-106A) | [19] |
| [`T1557.004`](/mitre/techniques/T1557-004.md) | Evil Twin | credential-access, collection | Listed | G0007 rows citing the October 2018 GRU indictment (hotel Wi-Fi) | [115][21] |
| [`T1012`](/mitre/techniques/T1012.md) | Query Registry | discovery | Listed | G0035 (TA18-074A) | [106] |
| [`T1016`](/mitre/techniques/T1016.md) | System Network Configuration Discovery | discovery | Listed | G0035 (TA18-074A); S0365 | [106][107] |
| [`T1018`](/mitre/techniques/T1018.md) | Remote System Discovery | discovery | Listed | G0035 (TA18-074A); S0365 | [106][107] |
| [`T1033`](/mitre/techniques/T1033.md) | System Owner/User Discovery | discovery | Listed | G0035 (TA18-074A) | [106] |
| [`T1049`](/mitre/techniques/T1049.md) | System Network Connections Discovery | discovery | Listed | G0082 (FireEye, Oct 2018) | [114] |
| [`T1057`](/mitre/techniques/T1057.md) | Process Discovery | discovery | Listed | G0082 (FireEye, Oct 2018) | [114] |
| [`T1069.002`](/mitre/techniques/T1069-002.md) | Domain Groups | discovery | Listed | G0035 (TA18-074A) | [106] |
| [`T1083`](/mitre/techniques/T1083.md) | File and Directory Discovery | discovery | Listed | G0035 (TA18-074A); G0007 (July 2018 indictment) | [106][115] |
| [`T1087.002`](/mitre/techniques/T1087-002.md) | Domain Account | discovery | Listed | G0035 (TA18-074A) | [106] |
| [`T1135`](/mitre/techniques/T1135.md) | Network Share Discovery | discovery | Listed | G0035 (TA18-074A); S0365 | [106][107] |
| [`T1021.001`](/mitre/techniques/T1021-001.md) | Remote Desktop Protocol | lateral-movement | Listed | G0035 (TA18-074A); G0045 (APT10 indictment); SamSam over RDP (AA18-337A, Described) | [106][112][57] |
| [`T1021.002`](/mitre/techniques/T1021-002.md) | SMB/Windows Admin Shares | lateral-movement | Listed | S0365 (PsExec over admin shares); Brambul's SMB brute force (TA18-149A, Described) | [107][24] |
| [`T1210`](/mitre/techniques/T1210.md) | Exploitation of Remote Services | lateral-movement | Listed | S0367 (TA18-201A) | [110] |
| [`T1570`](/mitre/techniques/T1570.md) | Lateral Tool Transfer | lateral-movement | Listed | S0365 | [107] |
| [`T1005`](/mitre/techniques/T1005.md) | Data from Local System | collection | Listed | G0035 (TA18-074A); G0045 (APT10 indictment); G0007 (July 2018 indictment) | [106][112][115] |
| [`T1074.001`](/mitre/techniques/T1074-001.md) | Local Data Staging | collection | Listed | G0035 (TA18-074A) | [106] |
| [`T1074.002`](/mitre/techniques/T1074-002.md) | Remote Data Staging | collection | Described | APT10 staged encrypted archives on other compromised hosts (DOJ, 20 Dec 2018) | [58] |
| [`T1113`](/mitre/techniques/T1113.md) | Screen Capture | collection | Listed | Screenshots taken through scheduled tasks (G0035, TA18-074A); G0007 (July 2018 indictment) | [106][11][115] |
| [`T1114`](/mitre/techniques/T1114.md) | Email Collection | collection | Listed | G0122 rows citing the Mabna indictment | [113] |
| [`T1114.002`](/mitre/techniques/T1114-002.md) | Remote Email Collection | collection | Listed | G0035 (TA18-074A); G0007 (July 2018 indictment) | [106][115] |
| [`T1114.003`](/mitre/techniques/T1114-003.md) | Email Forwarding Rule | collection | Listed | G0122 rows citing the Mabna indictment | [113] |
| [`T1115`](/mitre/techniques/T1115.md) | Clipboard Data | collection | Listed | G0082 (FireEye, Oct 2018) | [114] |
| [`T1119`](/mitre/techniques/T1119.md) | Automated Collection | collection | Listed | G0007 (July 2018 indictment) | [115] |
| [`T1560`](/mitre/techniques/T1560.md) | Archive Collected Data | collection | Listed | G0035 (TA18-074A); G0045 (APT10 indictment); G0007 (July 2018 indictment) | [106][112][115] |
| [`T1602.002`](/mitre/techniques/T1602-002.md) | Network Device Configuration Dump | collection | Described | Configuration files with password hashes and SNMP community strings pulled over SNMP or Smart Install to TFTP (TA18-106A) | [19] |
| [`T1071.001`](/mitre/techniques/T1071-001.md) | Web Protocols | command-and-control | Listed | G0082 (FireEye, Oct 2018); C0021 | [114][119] |
| [`T1071.002`](/mitre/techniques/T1071-002.md) | File Transfer Protocols | command-and-control | Listed | G0035 (TA18-074A) | [106] |
| [`T1090`](/mitre/techniques/T1090.md) | Proxy | command-and-control | Listed | C0013 | [117] |
| [`T1090.002`](/mitre/techniques/T1090-002.md) | External Proxy | command-and-control | Listed | G0007 (July 2018 indictment) | [115] |
| [`T1095`](/mitre/techniques/T1095.md) | Non-Application Layer Protocol | command-and-control | Listed | C0021 (library campaign data) | [119] |
| [`T1105`](/mitre/techniques/T1105.md) | Ingress Tool Transfer | command-and-control | Listed | G0035; G0045; G0082; C0013; C0021 | [106][112][114][117][116] |
| [`T1568.001`](/mitre/techniques/T1568-001.md) | Fast Flux DNS | command-and-control | Listed | G0045 rows citing the APT10 indictment | [112] |
| [`T1572`](/mitre/techniques/T1572.md) | Protocol Tunneling | command-and-control | Described | GRE tunnels on compromised routers; DNS redirected through GRE (TA18-106A, update of 19 Apr 2018) | [19] |
| [`T1573.002`](/mitre/techniques/T1573-002.md) | Asymmetric Cryptography | command-and-control | Listed | C0021 | [116] |
| [`T1020.001`](/mitre/techniques/T1020-001.md) | Traffic Duplication | exfiltration | Described | GRE tunnels used to mirror traffic from compromised routers (TA18-106A) | [19] |
| [`T1485`](/mitre/techniques/T1485.md) | Data Destruction | impact | Listed | S0365 (wipes writable files on mapped shares, Talos); G0082 (disks and logs wiped) | [107][5][114] |
| [`T1486`](/mitre/techniques/T1486.md) | Data Encrypted for Impact | impact | Listed | S0370 SamSam (network-wide encryption, AA18-337A); G0082 | [111][57][114] |
| [`T1489`](/mitre/techniques/T1489.md) | Service Stop | impact | Listed | S0365 | [107] |
| [`T1490`](/mitre/techniques/T1490.md) | Inhibit System Recovery | impact | Listed | S0365 deletes shadow copies and the backup catalog and disables recovery (Talos) | [107][5] |
| [`T1491.002`](/mitre/techniques/T1491-002.md) | External Defacement | impact | Listed | G0034 rows citing the NCSC Olympic statement (2020) | [109] |
| [`T1498`](/mitre/techniques/T1498.md) | Network Denial of Service | impact | Listed | G0007 rows citing the October 2018 GRU indictment; webstresser.org DDoS-for-hire taken down 24 Apr 2018 (Europol, mapping Inferred) | [115][67] |
| [`T1498.002`](/mitre/techniques/T1498-002.md) | Reflection Amplification | impact | Described | Memcached UDP reflection against GitHub, 1.35 Tbps, 28 Feb 2018 | [9][10] |
| [`T1529`](/mitre/techniques/T1529.md) | System Shutdown/Reboot | impact | Listed | S0365 (shuts hosts down, Talos); G0082 | [107][5][114] |
| [`T1561.001`](/mitre/techniques/T1561-001.md) | Disk Content Wipe | impact | Listed | S1010 VPNFilter kill command (Talos, 23 May 2018) | [108][22] |
| [`T1561.002`](/mitre/techniques/T1561-002.md) | Disk Structure Wipe | impact | Listed | G0082 (FireEye, Oct 2018) | [114] |
| [`T1565.001`](/mitre/techniques/T1565-001.md) | Stored Data Manipulation | impact | Listed | G0082: fraudulent SWIFT transactions inserted and transaction history altered (FireEye) | [114][41] |
| [`T1565.002`](/mitre/techniques/T1565-002.md) | Transmitted Data Manipulation | impact | Listed | G0082; FASTCash switch servers approve fraudulent requests (TA18-275A, Described) | [114][40] |
| [`T1565.003`](/mitre/techniques/T1565-003.md) | Runtime Data Manipulation | impact | Listed | G0082 (FireEye, Oct 2018) | [114] |

Not mapped, because no source opened prints or describes the behavior closely enough to choose an id: DNSpionage's DNS redirection and fake job sites, the Methbot and 3ve ad fraud, the Infraud marketplace, Marriott's, MyHeritage's, Cathay Pacific's and Under Armour's intrusions (no technique described), the Jiangsu MSS case, Spectre and Meltdown, and TSMC's misoperation [51][52][4][56][25][48][14][49][1][34]. Ryuk's software page S0446 is not used as a 2018 technique source, because Check Point's report is Reported and the ATT&CK rows were not tied to it [63].

### ATT&CK for ICS techniques

The library has no generated ICS technique pages, so these ids link to attack.mitre.org; each was checked in `data/attack/ics/technique_profiles.jsonl` [119]. Dragonfly's (and TEMP.Veles's) ICS mappings in the library's data are T0817 Drive-by Compromise and T0862 Supply Chain Compromise, which appear below tied to dated 2018 records; Sandworm Team's include T0819 and T0884, which no 2018 record opened here supports, so they are not rows (Confirmed [119]). TA18-074A's copying of VNC profiles and HMI screenshots from ICS-related hosts is collection from engineering hosts, but no ICS id was chosen for it (Inferred [11]).

| Id | Name (ATT&CK for ICS v20.0) | Tactic(s) | Basis | Dated event or report | Sources |
|---|---|---|---|---|---|
| [`T0817`](https://attack.mitre.org/techniques/T0817/) | Drive-by Compromise | initial-access | Described | Watering holes on ICS-related sites (TA18-074A, 15 Mar 2018); the library maps T0817 to G0035 at group level | [11][119] |
| [`T0862`](https://attack.mitre.org/techniques/T0862/) | Supply Chain Compromise | initial-access | Reported | Dragos reports compromises of ICS vendors and manufacturers in 2018 linked to XENOTIME; the library maps T0862 to G0088 at group level | [72][119] |
| [`T0842`](https://attack.mitre.org/techniques/T0842/) | Network Sniffing | discovery | Listed | S1010 VPNFilter; Talos's Modbus-monitoring sniffer plugin | [108][22] |
| [`T0830`](https://attack.mitre.org/techniques/T0830/) | Adversary-in-the-Middle | collection | Listed | S1010 VPNFilter (Talos, 23 May 2018) | [108][22] |

### ATT&CK groups, software and campaigns

Groups (every page exists under `/mitre/groups/`):

| Id | Group (library name) | The 2018 tie | Grade | Sources |
|---|---|---|---|---|
| [G0035](/mitre/groups/G0035.md) | Dragonfly | TA18-074A cites Symantec's Dragonfly report; 41 G0035 technique rows cite TA18-074A | Confirmed | [11][106] |
| [G0034](/mitre/groups/G0034.md) | Sandworm Team | S0365 Olympic Destroyer and S1010 VPNFilter per ATT&CK; the 2020 GRU indictment; the UK lists Sandworm among GRU names | Confirmed | [107][108][6][16] |
| [G0007](/mitre/groups/G0007.md) | APT28 (aliases include Sednit, Sofacy) | July and October 2018 indictments; VPNFilter per DOJ; Strontium domains; LoJax per ESET (Reported) | Confirmed | [115][29][21][23][35][62] |
| [G0016](/mitre/groups/G0016.md) | APT29 | C0021 overlaps suspected APT29 activity (Nov 2018) | Confirmed | [50][116] |
| [G0032](/mitre/groups/G0032.md) | Lazarus Group (aliases include HIDDEN COBRA) | Park Jin Hyok complaint; C0013 by similarity | Confirmed | [36][117][118] |
| [G0082](/mitre/groups/G0082.md) | APT38 | FireEye, 3 Oct 2018 | Confirmed | [41][114] |
| [G0122](/mitre/groups/G0122.md) | Silent Librarian | Mabna Institute indictment, 23 Mar 2018 | Confirmed | [13][113] |
| [G0045](/mitre/groups/G0045.md) | menuPass (alias APT10) | APT10 indictment and allied attribution, 20 Dec 2018 | Confirmed | [58][59][112] |
| [G0076](/mitre/groups/G0076.md) | Thrip | Symantec, 19 Jun 2018 | Confirmed | [26][119] |
| [G0107](/mitre/groups/G0107.md) | Whitefly | SingHealth, July 2018 (Symantec, Mar 2019) | Confirmed (the SingHealth attribution Reported) | [30][119] |
| [G0046](/mitre/groups/G0046.md) | FIN7 | Three members in custody, 1 Aug 2018 | Confirmed | [33][119] |
| [G0008](/mitre/groups/G0008.md) | Carbanak | Europol's arrest of the Carbanak and Cobalt leader (2018) | Confirmed | [66][119] |
| [G0088](/mitre/groups/G0088.md) | TEMP.Veles (alias XENOTIME) | FireEye's TRITON attribution and Dragos's vendor compromises | Reported | [71][72][119] |

Not mapped, because no source opened ties the activity to an ATT&CK group: the Jiangsu MSS defendants, the SamSam defendants, the Infraud and 3ve defendants, the webstresser administrators, DNSpionage (Talos linked it to no known actor) and the Olympic Destroyer operator as Talos saw it in February 2018 [49][54][4][52][67][51][5].

Software (pages exist under `/mitre/software/` except where noted):

| Id | Software | The 2018 tie | Sources |
|---|---|---|---|
| [S0365](/mitre/software/S0365.md) | Olympic Destroyer | 9 Feb 2018 | [5][107] |
| [S1010](/mitre/software/S1010.md) | VPNFilter | 23 May 2018 | [22][108] |
| [S0368](/mitre/software/S0368.md) | NotPetya | Attributed to the Russian military, 15 Feb 2018 | [7][8] |
| [S0366](/mitre/software/S0366.md) | WannaCry | Park Jin Hyok complaint, 6 Sep 2018 | [36] |
| [S0367](/mitre/software/S0367.md) | Emotet | TA18-201A, 20 Jul 2018 | [32][110] |
| [S0370](/mitre/software/S0370.md) | SamSam | Indictment 28 Nov; AA18-337A 3 Dec 2018 | [54][57][111] |
| [S0446](/mitre/software/S0446.md) | Ryuk | Check Point, Aug 2018 (Reported) | [63] |
| [S0397](/mitre/software/S0397.md) | LoJax | ESET, 27 Sep 2018 | [62][119] |
| [S0342](/mitre/software/S0342.md) | GreyEnergy | ESET, 17 Oct 2018 | [47][119] |
| [S0089](/mitre/software/S0089.md) | BlackEnergy | VPNFilter overlap (not definitive) and GreyEnergy's predecessor | [22][47] |
| [S0030](/mitre/software/S0030.md) | Carbanak | FIN7's adapted Carbanak malware (DOJ) | [33][119] |
| [S0261](/mitre/software/S0261.md) | Catchamas | Thrip, Jan 2018 | [26][119] |
| [S0029](/mitre/software/S0029.md) | PsExec | Olympic Destroyer, Thrip and TA18-074A | [5][26][11] |
| [S0002](/mitre/software/S0002.md) | Mimikatz | AA18-284A | [46] |
| [S0020](/mitre/software/S0020.md) | China Chopper | AA18-284A | [46] |
| [S0363](/mitre/software/S0363.md) | Empire (alias PowerShell Empire) | AA18-284A | [46][119] |
| [S0283](/mitre/software/S0283.md) | jRAT (alias jBiFrost) | AA18-284A's JBiFrost (alias match in the library's data) | [46][119] |
| [S0040](/mitre/software/S0040.md) | HTRAN (alias HUC Packet Transmit Tool) | AA18-284A's HUC Packet Transmitter (alias match in the library's data) | [46][119] |
| [S1009](https://attack.mitre.org/software/S1009/) | Triton (ICS; no library page) | FireEye's 2018 TRITON attribution (Reported) | [71][119] |

The library has no `/mitre/software/S1009.md` page; S1009 appears only in `data/attack/ics/software.jsonl` (Confirmed [119]). Not linked, because the library's data has no ATT&CK software object for them: Joanap, Brambul, GandCrab, Vcrodat, Kovter and the DNSpionage tooling (Confirmed [119]).

Campaigns (pages exist under `/mitre/campaigns/`):

| Id | Campaign | Window in library data | The 2018 tie | Sources |
|---|---|---|---|---|
| [C0021](/mitre/campaigns/C0021.md) | C0021 | 2018-11 to 2018-11 | Spearphishing overlapping suspected APT29 activity, 14 Nov 2018 | [50][116][119] |
| [C0013](/mitre/campaigns/C0013.md) | Operation Sharpshooter | 2017-09 to 2019-03 | Lazarus-like operation against nuclear, defense, government, energy and financial targets | [117][119] |
| [C0006](/mitre/campaigns/C0006.md) | Operation Honeybee | 2017-08 to 2018-02 | Window spans early 2018; not opened for this study | [119] |
| [C0014](/mitre/campaigns/C0014.md) | Operation Wocao | 2017-12 to 2019-12 | Window spans 2018; not opened for this study | [119] |
| [C0023](/mitre/campaigns/C0023.md) | Operation Ghost | 2013-09 to 2019-10 | Window spans 2018; not opened for this study | [119] |
| [C0033](/mitre/campaigns/C0033.md) | C0033 | 2016-05 to 2023-01 | Window spans 2018; not opened for this study | [119] |

Only C0021 and C0013 contribute techniques to the tables above; the other four are listed so a reader can find ATT&CK's 2018-era campaign objects (Confirmed for the windows [119]). The library's data has no campaign object for Olympic Destroyer, VPNFilter, the router campaign, Dragonfly's 2016 to 2018 activity, FASTCash or SamSam (Confirmed [119]).

### CWE and CAPEC

The CWE ids are those NVD, the vendor or KEV list for each CVE (Confirmed [87][88][89][90][91][92][93][94][95][96][98][99][100][103][104][105][123][86]). The CAPEC column lists the attack patterns the library's `cwe.jsonl` relates to that CWE, linked where a generated page exists; choosing the closest pattern is this study's reading (Inferred [120]).

| CWE | Weakness (library name) | CVEs from the 2018 record | CAPEC the library relates |
|---|---|---|---|
| CWE-20 | Improper Input Validation | CVE-2018-7600 (NVD), CVE-2018-0171 (Cisco), CVE-2018-0296 (NVD), CVE-2018-11776 (KEV) | broad class; none chosen |
| CWE-787 | Out-of-bounds Write | CVE-2018-0171 (NVD), CVE-2018-8174, CVE-2018-0802 | none in library data |
| CWE-416 | Use After Free | CVE-2018-4878 | none in library data |
| CWE-415 | Double Free | CVE-2018-0101 | none in library data |
| CWE-404 | Improper Resource Shutdown or Release | CVE-2018-8120 | none chosen (the library relates CAPEC-125 and others) |
| CWE-502 | Deserialization of Untrusted Data | CVE-2018-2628 | [CAPEC-586](/mitre/capec/CAPEC-586.md) Object Injection |
| CWE-22 | Improper Limitation of a Pathname to a Restricted Directory | CVE-2018-0296, CVE-2018-14847, CVE-2018-13379 (2019) | [CAPEC-126](/mitre/capec/CAPEC-126.md) Path Traversal |
| CWE-287 | Improper Authentication | CVE-2018-10561, CVE-2018-10933 | [CAPEC-115](/mitre/capec/CAPEC-115.md) Authentication Bypass (the library also relates CAPEC-650 and CAPEC-94) |
| CWE-94 | Improper Control of Generation of Code | CVE-2018-7602 | [CAPEC-242](/mitre/capec/CAPEC-242.md) Code Injection |
| CWE-434 | Unrestricted Upload of File with Dangerous Type | CVE-2018-15961 | [CAPEC-1](/mitre/capec/CAPEC-1.md) Accessing Functionality Not Properly Constrained by ACLs |
| CWE-120 | Buffer Copy without Checking Size of Input | CVE-2018-6789 | [CAPEC-100](/mitre/capec/CAPEC-100.md) Overflow Buffers |

TA18-106A names no CWE. Its conditions fit four weaknesses in the library's `cwe.jsonl`: CWE-306 Missing Authentication for Critical Functionality (Smart Install), CWE-319 Cleartext Transmission of Sensitive Information (Telnet, SNMPv1/v2c, TFTP), and CWE-1393 Use of Default Password and CWE-1188 Initialization of a Resource with an Insecure Default (defaults) (Confirmed that the ids exist [120]; the binding Inferred [19]).

The library's CAPEC records (CAPEC 3.9) tie patterns to techniques in the Enterprise table, and the 2018 record supplies an event for each (Confirmed as library data [120]; the event ties Inferred): [CAPEC-565](/mitre/capec/CAPEC-565.md) Password Spraying (T1110.003) for the Mabna actors and TA18-086A [77][113]; [CAPEC-49](/mitre/capec/CAPEC-49.md) Password Brute Forcing (T1110.001) for Brambul and Emotet [24][110]; [CAPEC-112](/mitre/capec/CAPEC-112.md) Brute Force (T1110) for TA18-106A and SamSam [19][57]; [CAPEC-55](/mitre/capec/CAPEC-55.md) Rainbow Table Password Cracking (T1110.002) for Dragonfly's cracking [11]; [CAPEC-650](/mitre/capec/CAPEC-650.md) Upload a Web Shell to a Web Server (T1505.003) for Dragonfly's web shells [11]; [CAPEC-163](/mitre/capec/CAPEC-163.md) Spear Phishing (T1566.001, T1566.002, T1598.003) for the GRU, Dragonfly, Mabna and APT10 [16][11][13][58]; [CAPEC-555](/mitre/capec/CAPEC-555.md) Remote Services with Stolen Credentials (T1133) for Dragonfly's VPN, RDP and OWA logons and SamSam's RDP [11][57]; [CAPEC-560](/mitre/capec/CAPEC-560.md) Use of Known Domain Credentials (T1078) for the MSP intrusions [42][58]; [CAPEC-94](/mitre/capec/CAPEC-94.md) Adversary in the Middle (T1557) for compromised routers [19]; and [CAPEC-158](/mitre/capec/CAPEC-158.md) Sniffing Network Traffic (T1040) for VPNFilter and the hotel Wi-Fi operations [22][21]. No CAPEC in the library maps T1187, T1189, T1190, T1021.001, T1486, T1490 or T1561.001 (Confirmed [120]). Through those records, CAPEC-565 and CAPEC-49 relate to CWE-521 Weak Password Requirements, CWE-307 Improper Restriction of Excessive Authentication Attempts and CWE-308 Use of Single-factor Authentication, and CAPEC-555 and CAPEC-560 to CWE-522 Insufficiently Protected Credentials (Confirmed [120]).

### D3FEND countermeasures

Pairings come from `data/attack/technique_to_d3fend.jsonl`; every linked page exists under `/mitre/d3fend/` [121][122]. The pairings are Confirmed as library data; matching each to an advisory control is this study's reading (Inferred).

| Technique from the record | D3FEND countermeasures the library maps (selection) | The 2018 control it matches |
|---|---|---|
| T1110.003 Password Spraying, T1110.001 Password Guessing | [Multi-factor Authentication](/mitre/d3fend/multi-factor-authentication.md), [Strong Password Policy](/mitre/d3fend/strong-password-policy.md), [Change Default Password](/mitre/d3fend/change-default-password.md), [Credential Hardening](/mitre/d3fend/credential-hardening.md) | NIST-aligned passwords and MFA (TA18-086A); unique non-default device passwords (TA18-106A) [77][19] |
| T1133 External Remote Services | [Session Termination](/mitre/d3fend/session-termination.md) (the only pairing) | MFA and VPN in front of RDP are the advisories' controls, not library pairings for T1133 [11][57] |
| T1021.001 Remote Desktop Protocol | [Remote Terminal Session Detection](/mitre/d3fend/remote-terminal-session-detection.md), [Network Traffic Filtering](/mitre/d3fend/network-traffic-filtering.md), [User Geolocation Logon Pattern Analysis](/mitre/d3fend/user-geolocation-logon-pattern-analysis.md) | Block RDP from untrusted addresses; 90-day RDP logs [11][57] |
| T1187 Forced Authentication, T1566.001 Spearphishing Attachment | [File Analysis](/mitre/d3fend/file-analysis.md), [Content Filtering](/mitre/d3fend/content-filtering.md); T1566.001 also [Email Filtering](/mitre/d3fend/email-filtering.md) and [Sender Reputation Analysis](/mitre/d3fend/sender-reputation-analysis.md) | Dragonfly's documents that fetch remote SMB resources; SMB blocked at the boundary; email gateway filtering (TA18-201A) [11][32] |
| T1505.003 Web Shell | [File Integrity Monitoring](/mitre/d3fend/file-integrity-monitoring.md), [Executable Allowlisting](/mitre/d3fend/executable-allowlisting.md), [Process Spawn Analysis](/mitre/d3fend/process-spawn-analysis.md) | Application directory allowlisting (TA18-074A) [11] |
| T1003.003 NTDS | [Credential Rotation](/mitre/d3fend/credential-rotation.md), [Credential Revocation](/mitre/d3fend/credential-revocation.md), [Multi-factor Authentication](/mitre/d3fend/multi-factor-authentication.md) | Fewer domain and enterprise admin accounts; resets after compromise [11] |
| T1557 Adversary-in-the-Middle, T1572 Protocol Tunneling | [Network Traffic Community Deviation](/mitre/d3fend/network-traffic-community-deviation.md), [Protocol Metadata Anomaly Detection](/mitre/d3fend/protocol-metadata-anomaly-detection.md); T1572 also [Outbound Traffic Filtering](/mitre/d3fend/outbound-traffic-filtering.md) | Unexpected GRE tunnels; outbound TFTP blocked (TA18-106A) [19] |
| T1199 Trusted Relationship | [User Geolocation Logon Pattern Analysis](/mitre/d3fend/user-geolocation-logon-pattern-analysis.md), [Remote Terminal Session Detection](/mitre/d3fend/remote-terminal-session-detection.md) | Scoped, time-limited MSP access through a dedicated VPN (TA18-276B) [42] |
| T1498.002 Reflection Amplification | [Inbound Session Volume Analysis](/mitre/d3fend/inbound-session-volume-analysis.md), [Inbound Traffic Filtering](/mitre/d3fend/inbound-traffic-filtering.md) | GitHub's move to Akamai; memcached not exposed on UDP [9][10] |
| T1542.001 System Firmware | [System Firmware Verification](/mitre/d3fend/system-firmware-verification.md), [Firmware Verification](/mitre/d3fend/firmware-verification.md) | LoJax survives OS reinstall and disk replacement [62]; firmware integrity checks (TA18-106A, for devices) [19] |
| T1565.002 Transmitted Data Manipulation | [Protocol Metadata Anomaly Detection](/mitre/d3fend/protocol-metadata-anomaly-detection.md), [Network Traffic Signature Analysis](/mitre/d3fend/network-traffic-signature-analysis.md) | Baseline transaction patterns on payment switches; mutual TLS (TA18-275A) [40] |
| T1486 Data Encrypted for Impact | [Restore File](/mitre/d3fend/restore-file.md), [File Integrity Monitoring](/mitre/d3fend/file-integrity-monitoring.md), [Decoy File](/mitre/d3fend/decoy-file.md) | A good backup strategy (AA18-337A) [57] |
| T1490 Inhibit System Recovery | [Restore Configuration](/mitre/d3fend/restore-configuration.md), [Restore Software](/mitre/d3fend/restore-software.md), [Software Inventory](/mitre/d3fend/software-inventory.md) | Olympic Destroyer's attack on shadow copies and recovery [5] |
| T1195.001 Compromise Software Dependencies and Development Tools | [Software Inventory](/mitre/d3fend/software-inventory.md), [Asset Vulnerability Enumeration](/mitre/d3fend/asset-vulnerability-enumeration.md), [Restore Software](/mitre/d3fend/restore-software.md) | event-stream removal and ownership change by npm [73] |
| T1561.001 Disk Content Wipe | [Disk Partitioning](/mitre/d3fend/disk-partitioning.md) (the only pairing) | VPNFilter's kill command; device replacement and resets are the advisory's control [22] |

The library data has no D3FEND mapping for T1602.002 Network Device Configuration Dump, T1020.001 Traffic Duplication, T1021.002 SMB/Windows Admin Shares, T1485 Data Destruction, T1498 Network Denial of Service, T1529 System Shutdown/Reboot, T1569.002 Service Execution, T1598.003 Spearphishing Link, T1686 Disable or Modify System Firewall or T1685.005 Clear Windows Event Logs; T1040 Network Sniffing has only [DNS Traffic Analysis](/mitre/d3fend/dns-traffic-analysis.md). None is invented here [121].

### Navigator layers

The study's techniques are saved as two ATT&CK Navigator layers pinned to ATT&CK v20: the Enterprise layer [navigator/library-layers/chronicle-2018.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/chronicle-2018.json) (the 127 techniques of the Enterprise table) and the ICS layer [navigator/case-studies/chronicle-2018-ics.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/case-studies/chronicle-2018-ics.json) (the 4 techniques of the ICS table), both listed on [the Navigator layers page](/navigator/index.md). Scores show the basis, not severity: 100 where the source or ATT&CK object prints the id (Listed), 70 where the source describes the behavior and this study assigns the id (Described), 50 where only a Reported source supports it, and 40 for an Inferred mapping. The 50 score for Reported follows the 2020 study; the 2019 and 2021 layers fold Reported into 40 (Confirmed for the format [122]). Each entry's comment names the source numbers in the Sources table below, and each technique is shown under every tactic it has in v20.0.

## Cross-cutting themes

**No zero-day required.** The year's state campaigns against network devices used defaults, legacy protocols and unauthenticated services (Confirmed [19][18]); SamSam used bought RDP passwords (Confirmed [57]); AA18-284A says even sophisticated groups use common public tools (Confirmed [46]). The advanced part of 2018 was persistence and patience, not exploits (Inferred).

**Trust was the attack surface.** Staging targets, MSPs, a new npm maintainer and a support widget's host each carried attacker code or access to a victim that trusted them (Confirmed [11][42][58][73][27]). The [SolarWinds study](/case-studies/SOLARWINDS_SUNBURST.md) shows the same pattern two years later (Inferred).

**The state named itself in court.** Indictments of GRU, MSS, IRGC-linked and North Korean operators in a single year made court filings the main public record of state operations (Confirmed [29][21][13][36][49][58]; the reading Inferred). That record describes conduct from 2006 to 2018, so 2018 is when it was told rather than when it happened (Inferred).

**Destruction got a stage.** Olympic Destroyer struck during a live opening ceremony, and VPNFilter carried a kill command and spiked in Ukraine (Confirmed [5][22]). Both were built to be noticed (Inferred).

**Money moved through crypto and the chain followed.** SamSam's ransom moved through Iran-based exchangers, and OFAC published the bitcoin addresses (Confirmed [55]). The GRU paid for infrastructure in cryptocurrency, per the July indictment (Confirmed [29]).

**The rulebook caught up on paper.** CSF 1.1, the CCPA, Singapore's critical-infrastructure law, EO 13848, the National Cyber Strategy, the CISA Act and Australia's Assistance and Access Act all date from 2018 (Confirmed [79][80][81][82][83][84][85]).

### What is overstated and what is understated

This section is the study's reading of the record (Inferred).

- **Overstated: the "Big Hack".** No primary opened confirms any implant, and Apple and AWS denied it in writing the day it ran [43][44].
- **Overstated: indictment totals as findings.** SamSam's over 200 victims and over $30 million, FIN7's 15 million cards and Infraud's $530 million are allegations [54][33][4].
- **Overstated: first-day breach counts.** Facebook's "almost 50 million" became about 30 million people with stolen tokens [39][75]; Marriott's figures were "up to" maximums on the first day, and no later revision was opened for this study [56].
- **Overstated: TSMC as an attack.** TSMC blamed a misoperation during tool installation and did not name WannaCry [34].
- **Overstated: back-dated attribution.** Today's ATT&CK attributions (FSB Center 16 for Dragonfly; Sandworm Team for Olympic Destroyer and VPNFilter) were not what 2018 sources said; Talos named no actor for Olympic Destroyer, and DOJ said Sofacy for VPNFilter [106][5][23][108].
- **Overstated: novelty of the year's "advanced" threats.** TA18-106A says no zero-days were needed and AA18-284A says sophisticated groups use public tools [19][46].
- **Overstated: exposure counts as impact.** VPNFilter's 500,000 is an estimate of infected devices, not of harm; Talos's 168,000 Smart Install systems are potentially exposed, not compromised [22][18].
- **Overstated: ATT&CK objects as the full picture.** VPNFilter has one Enterprise technique and SamSam five, while the advisories describe much more [108][111][57].
- **Understated: uneven hedging.** The UK said "almost certainly", FireEye "we believe", Talos "isn't definitive by any means", and the US alerts were flat [7][41][22][11].
- **Understated: the supply-chain and trust layer.** Staging targets, MSPs and trade-site watering holes recur across the year's advisories [11][42].
- **Understated: human-operated ransomware.** SamSam previewed the targeted, RDP-entered, network-wide encryption that defines later years [57][54].
- **Understated: ransomware cost.** IC3's 2018 ransomware total is about an eighth of what DOJ alleges SamSam alone cost over three years [65][54].
- **Understated: email fraud.** IC3's business email compromise losses were several hundred times its ransomware losses in 2018 [65].
- **Understated: thin D3FEND coverage of the edge.** No countermeasure for T1602.002, one for T1133 and one for T1561.001 [121].
- **Understated: KEV's lag.** KEV began in November 2021, so its dates for CVE-2018 entries are catalog history, not exploitation dates [86].
- **Understated: dates of conduct.** Many 2018 actions describe conduct from 2010 to 2017, so both dates should be given [49][29][58].

### Discrepancies in the record

- **VPNFilter's actor.** DOJ named the Sofacy Group with an alias list that includes sandworm; the UK lists VPNFilter under the GRU activities of its 4 October statement, but its entry cites only the April alert on Russian state-sponsored actors; ATT&CK associates S1010 with Sandworm Team through Cyclops Blink reporting [23][16][108].
- **VPNFilter's start.** The UK dates VPNFilter's infections to October 2017; Talos's Ukrainian spikes are in May 2018 [16][22].
- **The Mabna indictment's date.** DOJ announced the charges on 23 March 2018; TA18-086A dates the indictment to February 2018 [13][77].
- **The APT10 indictment's date.** DOJ unsealed it on 20 December 2018; ATT&CK's G0045 rows cite the indictment as of 17 December 2018 [58][112].
- **Facebook's counts.** Almost 50 million accounts (28 Sep) against about 30 million people with stolen tokens (12 Oct) [39][75].
- **Smart Install's CWE.** Cisco lists CWE-20 for CVE-2018-0171 and NVD lists CWE-787 [90][91].
- **Struts' CWE.** NVD lists NVD-CWE-noinfo for CVE-2018-11776 and KEV lists CWE-20 [98][86].
- **The Talos Smart Install post.** It is served at two addresses, blog.talosintelligence.com/critical-infrastructure-at-risk/ and the 2018/04 dated path; the content is the same post [18].
- **AA18-337A's address.** The advisory is served at cisa.gov/news-events/cybersecurity-advisories/aa18-337a and at cisa.gov/uscert/ncas/alerts/AA18-337A [57].
- **NotPetya's attribution.** The White House and the UK said the Russian military in February; the UK's October statement says the UK attributed it to the GRU in February 2018 [8][7][16].
- **ATT&CK versions.** The live site showed content v20.1 on G0035; the library and this study's names and tactics are v20.0 [106][119].

## Sources

All sources were opened on 11 November 2026. Grade is the source's evidence grade as used in this study. DOJ releases read through the press-release API or an Internet Archive snapshot are noted in Scope and method. Addresses shown as code rather than as links refuse automated link checkers (the sec.gov filings and the SEC press release, and Singapore Statutes Online); copy them into a browser to open them.

| # | Source | URL | Opened | Grade |
|---|---|---|---|---|
| 1 | Google Project Zero, Reading privileged memory with a side-channel, Jan 2018 | [googleprojectzero.blogspot.com](https://googleprojectzero.blogspot.com/2018/01/reading-privileged-memory-with-side.html) | 2026-11-11 | Confirmed |
| 2 | Meltdown and Spectre, the researchers' site | [meltdownattack.com](https://meltdownattack.com/) | 2026-11-11 | Confirmed |
| 3 | AWS, Security Bulletin AWS-2018-013, processor speculative execution | [aws.amazon.com](https://aws.amazon.com/security/security-bulletins/AWS-2018-013/) | 2026-11-11 | Confirmed |
| 4 | US DOJ, 36 defendants indicted (Infraud Organization), 7 Feb 2018 | [justice.gov](https://www.justice.gov/archives/opa/pr/thirty-six-defendants-indicted-alleged-roles-transnational-criminal-organization-responsible) | 2026-11-11 | Confirmed |
| 5 | Cisco Talos, Olympic Destroyer Takes Aim at Winter Olympics, 12 Feb 2018 | [blog.talosintelligence.com](https://blog.talosintelligence.com/olympic-destroyer/) | 2026-11-11 | Confirmed |
| 6 | US DOJ, Six Russian GRU officers charged (worldwide deployment of destructive malware), 19 Oct 2020 | [justice.gov](https://www.justice.gov/archives/opa/pr/six-russian-gru-officers-charged-connection-worldwide-deployment-destructive-malware-and) | 2026-11-11 | Confirmed |
| 7 | UK Government, Foreign Office Minister condemns Russia for NotPetya attacks, 15 Feb 2018 | [gov.uk](https://www.gov.uk/government/news/foreign-office-minister-condemns-russia-for-notpetya-attacks) | 2026-11-11 | Confirmed |
| 8 | The White House (archived), Statement from the Press Secretary, 15 Feb 2018 | [trumpwhitehouse.archives.gov](https://trumpwhitehouse.archives.gov/briefings-statements/statement-press-secretary-25/) | 2026-11-11 | Confirmed |
| 9 | GitHub, February 28th DDoS incident report, 1 Mar 2018 | [github.blog](https://github.blog/news-insights/company-news/ddos-incident-report/) | 2026-11-11 | Confirmed |
| 10 | Cloudflare, Memcrashed: major amplification attacks from UDP port 11211, 27 Feb 2018 | [blog.cloudflare.com](https://blog.cloudflare.com/memcrashed-major-amplification-attacks-from-port-11211/) | 2026-11-11 | Confirmed |
| 11 | DHS and FBI (US-CERT), TA18-074A, Russian Government Cyber Activity Targeting Energy and Other Critical Infrastructure Sectors, 15 Mar 2018 | [cisa.gov](https://www.cisa.gov/news-events/alerts/2018/03/15/russian-government-cyber-activity-targeting-energy-and-other-critical-infrastructure-sectors) | 2026-11-11 | Confirmed |
| 12 | US Treasury, press release sm0312 (Russian cyber actors; CAATSA and E.O. 13694), 15 Mar 2018 | [home.treasury.gov](https://home.treasury.gov/news/press-releases/sm0312) | 2026-11-11 | Confirmed |
| 13 | US DOJ, Nine Iranians charged (Mabna Institute), 23 Mar 2018 | [justice.gov](https://www.justice.gov/archives/opa/pr/nine-iranians-charged-conducting-massive-cyber-theft-campaign-behalf-islamic-revolutionary) | 2026-11-11 | Confirmed |
| 14 | Under Armour, Form 8-K exhibit 99.1, 29 Mar 2018 | `https://www.sec.gov/Archives/edgar/data/1336917/000133691718000012/exhibit991march292018.htm` | 2026-11-11 | Confirmed |
| 15 | Drupal, SA-CORE-2018-002, 28 Mar 2018 | [drupal.org](https://www.drupal.org/sa-core-2018-002) | 2026-11-11 | Confirmed |
| 16 | UK Government (FCO), UK exposes Russian cyber attacks, 4 Oct 2018 (updated the same day after the Dutch statement) | [gov.uk](https://www.gov.uk/government/news/uk-exposes-russian-cyber-attacks) | 2026-11-11 | Confirmed |
| 17 | Facebook (Meta) newsroom, restricting data access, 4 Apr 2018 | [about.fb.com](https://about.fb.com/news/2018/04/restricting-data-access/) | 2026-11-11 | Confirmed |
| 18 | Cisco Talos, Critical infrastructure at risk (Smart Install), 5 Apr 2018 | [blog.talosintelligence.com](https://blog.talosintelligence.com/critical-infrastructure-at-risk/) | 2026-11-11 | Confirmed |
| 19 | DHS, FBI and UK NCSC (US-CERT), TA18-106A, Russian State-Sponsored Cyber Actors Targeting Network Infrastructure Devices, 16 Apr 2018, updated 19 and 20 Apr | [cisa.gov](https://www.cisa.gov/news-events/alerts/2018/04/16/russian-state-sponsored-cyber-actors-targeting-network-infrastructure-devices) | 2026-11-11 | Confirmed |
| 20 | US SEC, press release 2018-71 (Altaba), 24 Apr 2018 | `https://www.sec.gov/news/press-release/2018-71` | 2026-11-11 | Confirmed |
| 21 | US DOJ, US charges Russian GRU officers with international hacking and related influence and disinformation operations (W.D. Pa.), 4 Oct 2018 | [justice.gov](https://www.justice.gov/archives/opa/pr/us-charges-russian-gru-officers-international-hacking-and-related-influence-and) | 2026-11-11 | Confirmed |
| 22 | Cisco Talos, New VPNFilter malware targets at least 500K networking devices worldwide, 23 May 2018 | [blog.talosintelligence.com](https://blog.talosintelligence.com/vpnfilter/) | 2026-11-11 | Confirmed |
| 23 | US DOJ, Justice Department announces actions to disrupt Advanced Persistent Threat 28 botnet, 23 May 2018 | [justice.gov](https://www.justice.gov/archives/opa/pr/justice-department-announces-actions-disrupt-advanced-persistent-threat-28-botnet-infected) | 2026-11-11 | Confirmed |
| 24 | DHS and FBI (US-CERT), TA18-149A, HIDDEN COBRA: Joanap Backdoor Trojan and Brambul Server Message Block Worm, 29 May 2018 | [cisa.gov](https://www.cisa.gov/news-events/alerts/2018/05/29/hidden-cobra-joanap-backdoor-trojan-and-brambul-server-message-block-worm) | 2026-11-11 | Confirmed |
| 25 | MyHeritage, statement about a cybersecurity incident, 4 Jun 2018 | [blog.myheritage.com](https://blog.myheritage.com/2018/06/myheritage-statement-about-a-cybersecurity-incident/) | 2026-11-11 | Confirmed |
| 26 | Symantec (security.com), Thrip hits satellite, telecoms and defense targets, 19 Jun 2018 | [security.com](https://www.security.com/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets) | 2026-11-11 | Confirmed |
| 27 | Ticketmaster UK, security incident page | [security.ticketmaster.co.uk](https://security.ticketmaster.co.uk/) | 2026-11-11 | Confirmed |
| 28 | Timehop, security incident page | [timehop.com](https://www.timehop.com/security) | 2026-11-11 | Confirmed |
| 29 | US DOJ, Grand jury indicts 12 Russian intelligence officers (2016 election), 13 Jul 2018 | [justice.gov](https://www.justice.gov/archives/opa/pr/grand-jury-indicts-12-russian-intelligence-officers-hacking-offenses-related-2016-election) | 2026-11-11 | Confirmed |
| 30 | Symantec (security.com), Whitefly: espionage group has Singapore in its sights, 6 Mar 2019 | [security.com](https://www.security.com/threat-intelligence/whitefly-espionage-singapore) | 2026-11-11 | Confirmed |
| 31 | LabCorp, Form 8-K, 16 Jul 2018 | `https://www.sec.gov/Archives/edgar/data/920148/000092014818000088/form8-kpr71618.htm` | 2026-11-11 | Confirmed |
| 32 | MS-ISAC and NCCIC (US-CERT), TA18-201A, Emotet Malware, 20 Jul 2018 | [cisa.gov](https://www.cisa.gov/news-events/alerts/2018/07/20/emotet-malware) | 2026-11-11 | Confirmed |
| 33 | US DOJ, Three members of notorious international cybercrime group FIN7 in custody, 1 Aug 2018 | [justice.gov](https://www.justice.gov/archives/opa/pr/three-members-notorious-international-cybercrime-group-fin7-custody-role-attacking-over-100) | 2026-11-11 | Confirmed |
| 34 | TSMC, news release 1969 (virus outbreak), 5 Aug 2018 | [pr.tsmc.com](https://pr.tsmc.com/english/news/1969) | 2026-11-11 | Confirmed |
| 35 | Microsoft On the Issues, We are taking new steps against broadening threats to democracy, 20 Aug 2018 | [blogs.microsoft.com](https://blogs.microsoft.com/on-the-issues/2018/08/20/we-are-taking-new-steps-against-broadening-threats-to-democracy/) | 2026-11-11 | Confirmed |
| 36 | US DOJ, North Korean regime-backed programmer charged (Park Jin Hyok), 6 Sep 2018 | [justice.gov](https://www.justice.gov/archives/opa/pr/north-korean-regime-backed-programmer-charged-conspiracy-conduct-multiple-cyber-attacks-and) | 2026-11-11 | Confirmed |
| 37 | US Treasury, press release sm473 (Park Jin Hyok and Chosun Expo Joint Venture), 6 Sep 2018 | [home.treasury.gov](https://home.treasury.gov/news/press-releases/sm473) | 2026-11-11 | Confirmed |
| 38 | New York Attorney General, record $148 million settlement with Uber, 26 Sep 2018 | [ag.ny.gov](https://ag.ny.gov/press-release/2018/ag-underwood-announces-record-148-million-settlement-uber-over-2016-data-breach) | 2026-11-11 | Confirmed |
| 39 | Facebook (Meta) newsroom, Security Update, 28 Sep 2018 | [about.fb.com](https://about.fb.com/news/2018/09/security-update/) | 2026-11-11 | Confirmed |
| 40 | DHS, Treasury and FBI (US-CERT), TA18-275A, HIDDEN COBRA: FASTCash Campaign, 2 Oct 2018, revised 21 Dec 2018 | [cisa.gov](https://www.cisa.gov/news-events/alerts/2018/10/02/hidden-cobra-fastcash-campaign) | 2026-11-11 | Confirmed |
| 41 | FireEye (now Google Cloud Threat Intelligence), APT38: details on new North Korean regime-backed threat group, 3 Oct 2018 | [cloud.google.com](https://cloud.google.com/blog/topics/threat-intelligence/apt38-details-on-new-north-korean-regime-backed-threat-group) | 2026-11-11 | Confirmed |
| 42 | NCCIC (US-CERT), TA18-276B, Advanced Persistent Threat Activity Exploiting Managed Service Providers, 3 Oct 2018 | [cisa.gov](https://www.cisa.gov/news-events/alerts/2018/10/03/advanced-persistent-threat-activity-exploiting-managed-service-providers) | 2026-11-11 | Confirmed |
| 43 | Apple Newsroom, What Businessweek got wrong about Apple, 4 Oct 2018 | [apple.com](https://www.apple.com/newsroom/2018/10/what-businessweek-got-wrong-about-apple/) | 2026-11-11 | Confirmed |
| 44 | AWS Security Blog, Setting the record straight on Bloomberg Businessweek's erroneous article, 4 Oct 2018 | [aws.amazon.com](https://aws.amazon.com/blogs/security/setting-the-record-straight-on-bloomberg-businessweeks-erroneous-article/) | 2026-11-11 | Confirmed |
| 45 | Google, Project Strobe (Google+ API bug and shutdown), 8 Oct 2018 | [blog.google](https://blog.google/technology/safety-security/project-strobe/) | 2026-11-11 | Confirmed |
| 46 | Australia, Canada, New Zealand, UK and US (CISA page), AA18-284A, Publicly Available Tools Seen in Cyber Incidents Worldwide, 11 Oct 2018 | [cisa.gov](https://www.cisa.gov/news-events/cybersecurity-advisories/aa18-284a) | 2026-11-11 | Confirmed |
| 47 | ESET WeLiveSecurity, GreyEnergy: updated arsenal of one of the most dangerous threat actors, 17 Oct 2018 | [welivesecurity.com](https://www.welivesecurity.com/2018/10/17/greyenergy-updated-arsenal-dangerous-threat-actors/) | 2026-11-11 | Confirmed |
| 48 | Cathay Pacific, data security event affecting passenger data, 24 Oct 2018 (date from page metadata) | [news.cathaypacific.com](https://news.cathaypacific.com/cathay-pacific-announces-data-security-event-affecting-passenger-data) | 2026-11-11 | Confirmed |
| 49 | US DOJ, Chinese intelligence officers and their recruited hackers and insiders conspired to steal aviation data, 30 Oct 2018 | [justice.gov](https://www.justice.gov/archives/opa/pr/chinese-intelligence-officers-and-their-recruited-hackers-and-insiders-conspired-steal) | 2026-11-11 | Confirmed |
| 50 | FireEye (now Google Cloud Threat Intelligence), Not so cozy: an uncomfortable examination of a suspected APT29 phishing campaign, 19 Nov 2018 | [cloud.google.com](https://cloud.google.com/blog/topics/threat-intelligence/not-so-cozy-an-uncomfortable-examination-of-a-suspected-apt29-phishing-campaign) | 2026-11-11 | Confirmed |
| 51 | Cisco Talos, DNSpionage campaign targets Middle East, 27 Nov 2018 | [blog.talosintelligence.com](https://blog.talosintelligence.com/dnspionage-campaign-targets-middle-east/) | 2026-11-11 | Confirmed |
| 52 | US Attorney's Office EDNY, Two international cybercriminal rings dismantled and eight defendants indicted, 27 Nov 2018 | [justice.gov](https://www.justice.gov/usao-edny/pr/two-international-cybercriminal-rings-dismantled-and-eight-defendants-indicted-causing) | 2026-11-11 | Confirmed |
| 53 | Google Security Blog, Industry collaboration leads to takedown of the 3ve ad fraud operation, 27 Nov 2018 | [security.googleblog.com](https://security.googleblog.com/2018/11/industry-collaboration-leads-to.html) | 2026-11-11 | Confirmed |
| 54 | US DOJ, Two Iranian men indicted for deploying ransomware (SamSam), 28 Nov 2018 | [justice.gov](https://www.justice.gov/archives/opa/pr/two-iranian-men-indicted-deploying-ransomware-extort-hospitals-municipalities-and-public) | 2026-11-11 | Confirmed |
| 55 | US Treasury, press release sm556 (SamSam bitcoin exchangers), 28 Nov 2018 | [home.treasury.gov](https://home.treasury.gov/news/press-releases/sm556) | 2026-11-11 | Confirmed |
| 56 | Marriott International, Form 8-K exhibit 99, 30 Nov 2018 | `https://www.sec.gov/Archives/edgar/data/1048286/000162828018014745/a2018ex99.htm` | 2026-11-11 | Confirmed |
| 57 | DHS NCCIC and FBI, AA18-337A, SamSam Ransomware, 3 Dec 2018 (also served at cisa.gov/uscert/ncas/alerts/AA18-337A) | [cisa.gov](https://www.cisa.gov/news-events/cybersecurity-advisories/aa18-337a) | 2026-11-11 | Confirmed |
| 58 | US DOJ, Two Chinese hackers associated with the Ministry of State Security charged (APT10), 20 Dec 2018 | [justice.gov](https://www.justice.gov/archives/opa/pr/two-chinese-hackers-associated-ministry-state-security-charged-global-computer-intrusion) | 2026-11-11 | Confirmed |
| 59 | UK Government, UK and allies reveal global scale of Chinese cyber campaign, 20 Dec 2018 | [gov.uk](https://www.gov.uk/government/news/uk-and-allies-reveal-global-scale-of-chinese-cyber-campaign) | 2026-11-11 | Confirmed |
| 60 | US Treasury, press release sm577 (GRU officers), 19 Dec 2018 | [home.treasury.gov](https://home.treasury.gov/news/press-releases/sm577) | 2026-11-11 | Confirmed |
| 61 | US Treasury, press release sm0410 (entities supporting the FSB), 11 Jun 2018 | [home.treasury.gov](https://home.treasury.gov/news/press-releases/sm0410) | 2026-11-11 | Confirmed |
| 62 | ESET WeLiveSecurity, LoJax: first UEFI rootkit found in the wild, 27 Sep 2018 | [welivesecurity.com](https://www.welivesecurity.com/2018/09/27/lojax-first-uefi-rootkit-found-wild-courtesy-sednit-group/) | 2026-11-11 | Confirmed (attribution Reported) |
| 63 | Check Point Research, Ryuk ransomware: a targeted campaign break-down, Aug 2018 | [research.checkpoint.com](https://research.checkpoint.com/2018/ryuk-ransomware-targeted-campaign-break/) | 2026-11-11 | Reported |
| 64 | No More Ransom, decryption tools | [nomoreransom.org](https://www.nomoreransom.org/en/decryption-tools.html) | 2026-11-11 | Confirmed |
| 65 | FBI IC3, 2018 Internet Crime Report (PDF) | [ic3.gov](https://www.ic3.gov/AnnualReport/Reports/2018_IC3Report.pdf) | 2026-11-11 | Confirmed |
| 66 | Europol, Mastermind behind EUR 1 billion cyber bank robbery arrested in Spain (summary text only) | [europol.europa.eu](https://www.europol.europa.eu/media-press/newsroom/news/mastermind-behind-eur-1-billion-cyber-bank-robbery-arrested-in-spain) | 2026-11-11 | Confirmed |
| 67 | Europol, World's biggest marketplace selling internet-paralysing DDoS attacks taken down, Apr 2018 (summary text only) | [europol.europa.eu](https://www.europol.europa.eu/media-press/newsroom/news/world%E2%80%99s-biggest-marketplace-selling-internet-paralysing-ddos-attacks-taken-down) | 2026-11-11 | Confirmed |
| 68 | FBI IC3, PSA I-052518-PSA (VPNFilter), 25 May 2018 | [ic3.gov](https://www.ic3.gov/PSA/2018/PSA180525) | 2026-11-11 | Confirmed |
| 69 | US-CERT, TA18-145A, Cyber Actors Target Home and Office Routers and Networked Devices Worldwide, 25 May 2018 | [cisa.gov](https://www.cisa.gov/news-events/alerts/2018/05/25/cyber-actors-target-home-and-office-routers-and-networked-devices-worldwide) | 2026-11-11 | Confirmed |
| 70 | Marriott newsroom, Marriott announces Starwood guest reservation database security incident, 30 Nov 2018 (title and date at this address; body from the archived 2018 address) | [news.marriott.com](https://news.marriott.com/news/2018/11/30/marriott-announces-starwood-guest-reservation-database-security-incident) | 2026-11-11 | Confirmed |
| 71 | FireEye (now Google Cloud Threat Intelligence), TRITON attribution: Russian government-owned lab most likely built tools, 23 Oct 2018 | [cloud.google.com](https://cloud.google.com/blog/topics/threat-intelligence/triton-attribution-russian-government-owned-lab-most-likely-built-tools/) | 2026-11-11 | Reported |
| 72 | Dragos, XENOTIME threat group page | [dragos.com](https://www.dragos.com/threat/xenotime/) | 2026-11-11 | Reported |
| 73 | npm blog, Details about the event-stream incident, Nov 2018 | [blog.npmjs.org](https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident) | 2026-11-11 | Confirmed |
| 74 | Gentoo, Infrastructure incident report 2018-06-28 GitHub | [wiki.gentoo.org](https://wiki.gentoo.org/wiki/Project:Infrastructure/Incident_reports/2018-06-28_Github) | 2026-11-11 | Confirmed |
| 75 | Facebook (Meta) newsroom, An update on the security issue, 12 Oct 2018 | [about.fb.com](https://about.fb.com/news/2018/10/update-on-security-issue/) | 2026-11-11 | Confirmed |
| 76 | Google, Expediting changes to Google+, 10 Dec 2018 | [blog.google](https://blog.google/technology/safety-security/expediting-changes-google-plus/) | 2026-11-11 | Confirmed |
| 77 | US-CERT, TA18-086A, Brute Force Attacks Conducted by Cyber Actors, 27 Mar 2018 | [cisa.gov](https://www.cisa.gov/news-events/alerts/2018/03/27/brute-force-attacks-conducted-cyber-actors) | 2026-11-11 | Confirmed |
| 78 | govinfo, Public Law 115-141, Consolidated Appropriations Act, 2018 | [govinfo.gov](https://www.govinfo.gov/app/details/PLAW-115publ141) | 2026-11-11 | Confirmed |
| 79 | NIST, NIST releases version 1.1 of its Cybersecurity Framework, 16 Apr 2018 | [nist.gov](https://www.nist.gov/news-events/news/2018/04/nist-releases-version-11-its-popular-cybersecurity-framework) | 2026-11-11 | Confirmed |
| 80 | California Legislative Information, AB-375, California Consumer Privacy Act of 2018 | [leginfo.legislature.ca.gov](https://leginfo.legislature.ca.gov/faces/billNavClient.xhtml?bill_id=201720180AB375) | 2026-11-11 | Confirmed |
| 81 | Singapore Statutes Online, Cybersecurity Act 2018 | `https://sso.agc.gov.sg/Act/CA2018` | 2026-11-11 | Confirmed |
| 82 | Federal Register, Executive Order 13848, 14 Sep 2018 | [federalregister.gov](https://www.federalregister.gov/documents/2018/09/14/2018-20203/imposing-certain-sanctions-in-the-event-of-foreign-interference-in-a-united-states-election) | 2026-11-11 | Confirmed |
| 83 | The White House (archived), National Cyber Strategy announcement, 20 Sep 2018 | [trumpwhitehouse.archives.gov](https://trumpwhitehouse.archives.gov/articles/president-trump-unveils-americas-first-cybersecurity-strategy-15-years/) | 2026-11-11 | Confirmed |
| 84 | govinfo, Public Law 115-278, Cybersecurity and Infrastructure Security Agency Act of 2018 | [govinfo.gov](https://www.govinfo.gov/app/details/PLAW-115publ278) | 2026-11-11 | Confirmed |
| 85 | Federal Register of Legislation (Australia), Telecommunications and Other Legislation Amendment (Assistance and Access) Act 2018, C2018A00148 | [legislation.gov.au](https://www.legislation.gov.au/C2018A00148/latest/text) | 2026-11-11 | Confirmed |
| 86 | CISA, Known Exploited Vulnerabilities catalog JSON, version 2026.11.10 | [cisa.gov](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) | 2026-11-11 | Confirmed |
| 87 | NIST NVD, CVE-2018-0101 (API 2.0) | [nvd.nist.gov](https://nvd.nist.gov/vuln/detail/CVE-2018-0101) | 2026-11-11 | Confirmed |
| 88 | NIST NVD, CVE-2018-4878 (API 2.0) | [nvd.nist.gov](https://nvd.nist.gov/vuln/detail/CVE-2018-4878) | 2026-11-11 | Confirmed |
| 89 | NIST NVD, CVE-2018-7600 record (API 2.0) | [services.nvd.nist.gov](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2018-7600) | 2026-11-11 | Confirmed |
| 90 | Cisco, cisco-sa-20180328-smi2, Smart Install remote code execution (CVE-2018-0171), with later updates | [sec.cloudapps.cisco.com](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-smi2) | 2026-11-11 | Confirmed |
| 91 | NIST NVD, CVE-2018-0171 record (API 2.0) | [services.nvd.nist.gov](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2018-0171) | 2026-11-11 | Confirmed |
| 92 | NIST NVD, CVE-2018-2628 (API 2.0) | [nvd.nist.gov](https://nvd.nist.gov/vuln/detail/CVE-2018-2628) | 2026-11-11 | Confirmed |
| 93 | NIST NVD, CVE-2018-10561 (API 2.0) | [nvd.nist.gov](https://nvd.nist.gov/vuln/detail/CVE-2018-10561) | 2026-11-11 | Confirmed |
| 94 | NIST NVD, CVE-2018-8174 (API 2.0) | [nvd.nist.gov](https://nvd.nist.gov/vuln/detail/CVE-2018-8174) | 2026-11-11 | Confirmed |
| 95 | NIST NVD, CVE-2018-0296 (API 2.0) | [nvd.nist.gov](https://nvd.nist.gov/vuln/detail/CVE-2018-0296) | 2026-11-11 | Confirmed |
| 96 | NIST NVD, CVE-2018-14847 (API 2.0) | [nvd.nist.gov](https://nvd.nist.gov/vuln/detail/CVE-2018-14847) | 2026-11-11 | Confirmed |
| 97 | NIST NVD, CVE-2018-8453 (API 2.0), with the KEV entries for the other Microsoft zero-days of 2018 | [nvd.nist.gov](https://nvd.nist.gov/vuln/detail/CVE-2018-8453) | 2026-11-11 | Confirmed |
| 98 | NIST NVD, CVE-2018-11776 (API 2.0) | [nvd.nist.gov](https://nvd.nist.gov/vuln/detail/CVE-2018-11776) | 2026-11-11 | Confirmed |
| 99 | NIST NVD, CVE-2018-15961 (API 2.0) | [nvd.nist.gov](https://nvd.nist.gov/vuln/detail/CVE-2018-15961) | 2026-11-11 | Confirmed |
| 100 | NIST NVD, CVE-2018-10933 (API 2.0) | [nvd.nist.gov](https://nvd.nist.gov/vuln/detail/CVE-2018-10933) | 2026-11-11 | Confirmed |
| 101 | NIST NVD, CVE-2018-1002105 (API 2.0) | [nvd.nist.gov](https://nvd.nist.gov/vuln/detail/CVE-2018-1002105) | 2026-11-11 | Confirmed |
| 102 | NIST NVD, CVE-2018-20062 (API 2.0) | [nvd.nist.gov](https://nvd.nist.gov/vuln/detail/CVE-2018-20062) | 2026-11-11 | Confirmed |
| 103 | NIST NVD, CVE-2018-0802 (API 2.0) | [nvd.nist.gov](https://nvd.nist.gov/vuln/detail/CVE-2018-0802) | 2026-11-11 | Confirmed |
| 104 | NIST NVD, CVE-2018-6789 (API 2.0) | [nvd.nist.gov](https://nvd.nist.gov/vuln/detail/CVE-2018-6789) | 2026-11-11 | Confirmed |
| 105 | NIST NVD, CVE-2018-13379 (API 2.0), with the CVE-2018-15982 and CVE-2018-20250 records | [nvd.nist.gov](https://nvd.nist.gov/vuln/detail/CVE-2018-13379) | 2026-11-11 | Confirmed |
| 106 | MITRE ATT&CK, group G0035 Dragonfly (site at content v20.1) | [attack.mitre.org](https://attack.mitre.org/groups/G0035/) | 2026-11-11 | Confirmed |
| 107 | MITRE ATT&CK, software S0365 Olympic Destroyer | [attack.mitre.org](https://attack.mitre.org/software/S0365/) | 2026-11-11 | Confirmed |
| 108 | MITRE ATT&CK, software S1010 VPNFilter | [attack.mitre.org](https://attack.mitre.org/software/S1010/) | 2026-11-11 | Confirmed |
| 109 | MITRE ATT&CK, group G0034 Sandworm Team | [attack.mitre.org](https://attack.mitre.org/groups/G0034/) | 2026-11-11 | Confirmed |
| 110 | MITRE ATT&CK, software S0367 Emotet | [attack.mitre.org](https://attack.mitre.org/software/S0367/) | 2026-11-11 | Confirmed |
| 111 | MITRE ATT&CK, software S0370 SamSam | [attack.mitre.org](https://attack.mitre.org/software/S0370/) | 2026-11-11 | Confirmed |
| 112 | MITRE ATT&CK, group G0045 menuPass | [attack.mitre.org](https://attack.mitre.org/groups/G0045/) | 2026-11-11 | Confirmed |
| 113 | MITRE ATT&CK, group G0122 Silent Librarian | [attack.mitre.org](https://attack.mitre.org/groups/G0122/) | 2026-11-11 | Confirmed |
| 114 | MITRE ATT&CK, group G0082 APT38 | [attack.mitre.org](https://attack.mitre.org/groups/G0082/) | 2026-11-11 | Confirmed |
| 115 | MITRE ATT&CK, group G0007 APT28 | [attack.mitre.org](https://attack.mitre.org/groups/G0007/) | 2026-11-11 | Confirmed |
| 116 | MITRE ATT&CK, campaign C0021 | [attack.mitre.org](https://attack.mitre.org/campaigns/C0021/) | 2026-11-11 | Confirmed |
| 117 | MITRE ATT&CK, campaign C0013 Operation Sharpshooter | [attack.mitre.org](https://attack.mitre.org/campaigns/C0013/) | 2026-11-11 | Confirmed |
| 118 | MITRE ATT&CK, group G0032 Lazarus Group | [attack.mitre.org](https://attack.mitre.org/groups/G0032/) | 2026-11-11 | Confirmed |
| 119 | TeamStarWolf library data on main: `data/attack/` (technique profiles, groups, software, campaigns, campaign profiles, group and software technique maps, `superseded_by.jsonl`) and `data/attack/ics/` | [github.com/TeamStarWolf/TeamStarWolf](https://github.com/TeamStarWolf/TeamStarWolf/tree/main/data/attack) | 2026-11-11 | Confirmed |
| 120 | TeamStarWolf library data on main: `data/weaknesses/capec.jsonl` (CAPEC 3.9) and `cwe.jsonl` | [github.com/TeamStarWolf/TeamStarWolf](https://github.com/TeamStarWolf/TeamStarWolf/tree/main/data/weaknesses) | 2026-11-11 | Confirmed |
| 121 | TeamStarWolf library data on main: `data/attack/technique_to_d3fend.jsonl` and `mitigation_to_technique.jsonl` | [github.com/TeamStarWolf/TeamStarWolf](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/attack/technique_to_d3fend.jsonl) | 2026-11-11 | Confirmed |
| 122 | TeamStarWolf library tree on main: `mitre/` pages, `navigator/library-layers/` (the chronicle-2019 layer format) and the home studies under `case-studies/` | [github.com/TeamStarWolf/TeamStarWolf](https://github.com/TeamStarWolf/TeamStarWolf/tree/main/mitre) | 2026-11-11 | Confirmed |
| 123 | NIST NVD, CVE-2018-7602 record (API 2.0) | [services.nvd.nist.gov](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2018-7602) | 2026-11-11 | Confirmed |

*© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.*

*© The MITRE Corporation. Includes material from the Common Weakness Enumeration (CWE™), used under the CWE Terms of Use. https://cwe.mitre.org/*

*© The MITRE Corporation. Includes material from the Common Attack Pattern Enumeration and Classification (CAPEC™), used under the CAPEC Terms of Use. https://capec.mitre.org/*

*© The MITRE Corporation. Includes material from MITRE D3FEND™, used under the D3FEND Terms of Use. https://d3fend.mitre.org/*

*The terms for every MITRE dataset used here are recorded in [THIRD_PARTY_NOTICES.md](/THIRD_PARTY_NOTICES.md).*

## Related references

- [Notable Incidents](/NOTABLE_INCIDENTS.md), [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [CVE Reference](/CVE_REFERENCE.md)
- [CWE Reference](/CWE_REFERENCE.md), [CAPEC Reference](/CAPEC_REFERENCE.md), [D3FEND Reference](/D3FEND_REFERENCE.md)
- [Ransomware Defense](/RANSOMWARE_DEFENSE_REFERENCE.md), [ICS and OT Security](/ICS_OT_SECURITY_REFERENCE.md), [ICS ATT&CK Atlas](/ICS_ATTACK_ATLAS.md), [Supply Chain Security](/SUPPLY_CHAIN_SECURITY.md), [Cloud Attack Reference](/CLOUD_ATTACK_REFERENCE.md)
- Home studies: [Sandworm](/case-studies/SANDWORM_OPERATIONS.md); [Russia-attributed actors](/case-studies/THREAT_ACTORS_RUSSIA.md); [North Korea-attributed actors](/case-studies/THREAT_ACTORS_NORTH_KOREA.md); [Iran-attributed actors](/case-studies/THREAT_ACTORS_IRAN.md); [China-attributed actors](/case-studies/THREAT_ACTORS_CHINA.md); [npm supply-chain attacks](/case-studies/NPM_SUPPLY_CHAIN_ATTACKS.md)
- Related studies: [SolarWinds and SUNBURST](/case-studies/SOLARWINDS_SUNBURST.md); [APT41: the public record](/case-studies/APT41_PUBLIC_RECORD.md); [Stuxnet](/case-studies/STUXNET.md); [ICS attacks and advisories, 2024 to 2026](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md); [Log4Shell](/case-studies/LOG4SHELL.md); [Hugging Face supply chain](/case-studies/HUGGING_FACE_SUPPLY_CHAIN.md); [The ransomware ecosystem, 2019 to 2026](/case-studies/RANSOMWARE_ECOSYSTEM.md)
- Series: [2016](/case-studies/CHRONICLE_2016.md), [2017](/case-studies/CHRONICLE_2017.md), [2019](/case-studies/CHRONICLE_2019.md), [2020](/case-studies/CHRONICLE_2020.md), [2021](/case-studies/CHRONICLE_2021.md)
- Groups: [G0035 Dragonfly](/mitre/groups/G0035.md), [G0034 Sandworm Team](/mitre/groups/G0034.md), [G0007 APT28](/mitre/groups/G0007.md), [G0016 APT29](/mitre/groups/G0016.md), [G0032 Lazarus Group](/mitre/groups/G0032.md), [G0082 APT38](/mitre/groups/G0082.md), [G0122 Silent Librarian](/mitre/groups/G0122.md), [G0045 menuPass](/mitre/groups/G0045.md), [G0076 Thrip](/mitre/groups/G0076.md), [G0107 Whitefly](/mitre/groups/G0107.md), [G0046 FIN7](/mitre/groups/G0046.md), [G0008 Carbanak](/mitre/groups/G0008.md), [G0088 TEMP.Veles](/mitre/groups/G0088.md)
- Software: [S0365 Olympic Destroyer](/mitre/software/S0365.md), [S1010 VPNFilter](/mitre/software/S1010.md), [S0368 NotPetya](/mitre/software/S0368.md), [S0366 WannaCry](/mitre/software/S0366.md), [S0367 Emotet](/mitre/software/S0367.md), [S0370 SamSam](/mitre/software/S0370.md), [S0446 Ryuk](/mitre/software/S0446.md), [S0397 LoJax](/mitre/software/S0397.md), [S0342 GreyEnergy](/mitre/software/S0342.md), [S0089 BlackEnergy](/mitre/software/S0089.md), [S0030 Carbanak](/mitre/software/S0030.md), [S0261 Catchamas](/mitre/software/S0261.md), [S0029 PsExec](/mitre/software/S0029.md), [S0002 Mimikatz](/mitre/software/S0002.md), [S0020 China Chopper](/mitre/software/S0020.md), [S0363 Empire](/mitre/software/S0363.md), [S0283 jRAT](/mitre/software/S0283.md), [S0040 HTRAN](/mitre/software/S0040.md)
- Campaigns: [C0021](/mitre/campaigns/C0021.md), [C0013 Operation Sharpshooter](/mitre/campaigns/C0013.md)
- Techniques: [T1133 External Remote Services](/mitre/techniques/T1133.md), [T1110.003 Password Spraying](/mitre/techniques/T1110-003.md), [T1187 Forced Authentication](/mitre/techniques/T1187.md), [T1602.002 Network Device Configuration Dump](/mitre/techniques/T1602-002.md), [T1557 Adversary-in-the-Middle](/mitre/techniques/T1557.md), [T1199 Trusted Relationship](/mitre/techniques/T1199.md), [T1021.001 Remote Desktop Protocol](/mitre/techniques/T1021-001.md), [T1486 Data Encrypted for Impact](/mitre/techniques/T1486.md), [T1490 Inhibit System Recovery](/mitre/techniques/T1490.md), [T1498.002 Reflection Amplification](/mitre/techniques/T1498-002.md), [T1542.001 System Firmware](/mitre/techniques/T1542-001.md), [T1565.001 Stored Data Manipulation](/mitre/techniques/T1565-001.md)
- CAPEC: [CAPEC-565](/mitre/capec/CAPEC-565.md), [CAPEC-555](/mitre/capec/CAPEC-555.md), [CAPEC-163](/mitre/capec/CAPEC-163.md), [CAPEC-94](/mitre/capec/CAPEC-94.md), [CAPEC-586](/mitre/capec/CAPEC-586.md), [CAPEC-126](/mitre/capec/CAPEC-126.md)
- [Navigator layers](/navigator/index.md), including this study's layers, [chronicle-2018.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/chronicle-2018.json) and [chronicle-2018-ics.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/case-studies/chronicle-2018-ics.json)
