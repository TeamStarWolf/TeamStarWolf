# Oracle PeopleSoft CVE-2026-35273 and the ShinyHunters Mass Exploitation of 2026: A Case Study

*A TeamStarWolf case study. Published 11 November 2026; every source checked as of that date.*

[All case studies](/case-studies/README.md) · Related: [The Year 2026 in Intrusions](/case-studies/CHRONICLE_2026.md), [The Instructure Canvas Breach and ShinyHunters Extortion of 2026](/case-studies/INSTRUCTURE_CANVAS_BREACH_2026.md), [The Cl0p File-Transfer Breaches](/case-studies/CL0P_FILE_TRANSFER_2023.md), [Change Healthcare 2024](/case-studies/CHANGE_HEALTHCARE_2024.md), [SharePoint ToolShell 2025](/case-studies/SHAREPOINT_TOOLSHELL_2025.md), [Notable Incidents](/NOTABLE_INCIDENTS.md), [CVE Reference](/CVE_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Higher education and public-sector IT and security leaders, ERP and PeopleSoft administrators, vulnerability management leads, detection engineers and incident responders

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 19 min (4,338 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want the dated record of the 2026 PeopleSoft CVE-2026-35273 zero-day and September WAF-bypass waves, what the vendor, KEV and GTIG each said, or which patch and hunt steps the case argues for

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [Part 1: what happened](#part-1-what-happened), [Part 5: the defender and vulnerability-management view](#part-5-the-defender-and-vulnerability-management-view)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md), [The Instructure Canvas Breach and ShinyHunters Extortion of 2026: A Case Study](/case-studies/INSTRUCTURE_CANVAS_BREACH_2026.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive summary

The people in this story are students, alumni and job applicants. On 10 June 2026 the University of Nottingham told its students that a significant amount of data in its student record system had been accessed by an outside party, affecting current students and alumni [10] (**Confirmed**). Have I Been Pwned later loaded 454,635 unique email addresses from that breach, with passport numbers, ethnicities, disabilities and academic records among the data classes [11] (**Confirmed** as HIBP's record). In September ShinyHunters defaced the FBI's recruitment site and claimed data on FBI employees and applicants. An FBI spokesperson told 404 Media a PeopleSoft zero-day was exploited [15], and a later FBI statement relayed by Krebs named CVE-2026-35273, by then a patched n-day [16] (**Reported**).

News reports tie both to one flaw in Oracle PeopleSoft, the suite that holds HR, payroll and student records [8] [13] [16] (**Reported**). Mandiant and Google Threat Intelligence Group (GTIG) saw UNC6240, which they track as ShinyHunters, exploit CVE-2026-35273 as a zero-day from 27 May to 9 June 2026 [7] (**Confirmed**). Oracle published an out-of-band Security Alert on 10 June [1] and CISA added the CVE to KEV on 12 June with a three-day deadline [4] (**Confirmed**). Three months later the actor came back against organizations that had blocked the vulnerable path with WAF rules instead of patching, and walked around those rules with an encoded path [8] (**Confirmed**).

### Key facts at a glance

| Field | Value |
|---|---|
| Vulnerability | CVE-2026-35273, PeopleSoft Enterprise PeopleTools, component Updates Environment Management, over HTTP [1] (**Confirmed**) |
| Affected versions | PeopleTools 8.61 and 8.62; PeopleSoft Enterprise Applications customers may also be affected; earlier unsupported releases likely affected [1] (**Confirmed**) |
| Severity | CVSS 3.1 9.8, unauthenticated, may result in remote code execution [1]; CISA SSVC: exploitation active, automatable, technical impact total [3] (**Confirmed**) |
| Weakness | CWE-306 in NVD and KEV [3] [4] (**Confirmed**); ZDI says the one CVE covers three chained issues: SSRF, file-path control and deserialization [9] (**Confirmed** as ZDI states it) |
| Zero-day window | 27 May to 9 June 2026, before Oracle's 10 June alert [7] (**Confirmed**) |
| KEV | Added 12 June 2026, due 15 June, known ransomware campaign use "Known" [4] [5] (**Confirmed**) |
| Actor | UNC6240, tracked by GTIG as ShinyHunters [7]; ATT&CK [G1057](/mitre/groups/G1057.md) [12] (**Confirmed**) |
| Scale | More than 100 organizations notified in June, 68% in higher education, mostly in the US; some compromised, no count given [7]. Web shells on dozens of systems in September [8] (**Confirmed**) |
| Second wave | September 2026, WAF and proxy rules bypassed with an encoded path [8] (**Confirmed**) |

### Key findings

- **The vendor page was the quietest record.** Oracle's alert does not mention exploitation [1], while CISA's SSVC entry the next day records exploitation as active [3] and KEV followed on 12 June [4] (**Confirmed**). A team reading only the vendor alert would have missed the urgency (**Inferred**).
- **The exploit predates the fix.** Staging infrastructure was set up on 27 May, and stolen data was on the leak site on 9 June, a day before Oracle's alert [7] (**Confirmed**).
- **A stopgap became the attack surface.** In September, organizations that had applied WAF rules but not patched were exploited through path encoding the rules did not normalize [8] (**Confirmed**). GTIG's words: WAF rules and path-based blocking "are not a substitute for patching" [8].
- **One CVE id hides three flaws.** ZDI describes an SSRF in the Integration Gateway, external control of a file path and unsafe deserialization in the Environment Management Hub, with separate CVEs still being coordinated [9] (**Confirmed** as ZDI states it).

### Top recommendations

1. Patch PeopleTools from Oracle's Security Alert patch availability document [1]; treat WAF rules as a bridge, never as the fix [8] (**Confirmed** guidance).
2. Disable the Environment Management Hub or remove PSEMHUB where Oracle's guidance allows, and block external access to the PSEMHUB and Integration Broker listening-connector paths on the normalized path [7] [8] (**Confirmed** guidance).
3. Hunt before declaring clean: WebLogic access logs, unexpected JSP, JSPX and EXE files, MeshCentral agents, shells spawned by the WebLogic Java process, and outbound SMB on port 445 [7] [8] (**Confirmed** guidance). Oracle's alert does not say whether patching removes access an attacker already gained [14] (**Reported**). GTIG's advice to treat web-shell hosts as compromised assumes it does not [8] (**Confirmed** guidance).
4. Where a web shell is confirmed, treat the host as compromised, rotate every credential the PeopleSoft tier can read, review database audit logs for bulk HR, payroll and student exports, and prepare for extortion [8] (**Confirmed** guidance).

## Scope and method

This brief covers CVE-2026-35273 from its reservation on 1 April 2026 to the KEV catalog of 10 November 2026: the zero-day wave, the September n-day wave, the FBI recruitment-site intrusion and the arrests that followed. Tradecraft stays at advisory level: flaw classes and tools are named, request formats and payloads are not. The leak site was not visited. Every source was opened on 11 November 2026. Not opened, so never cited as a source: the FBI statement on fbijobs.gov (it returned HTTP 403), Reuters, 404 Media, BleepingComputer's WAF-bypass story, the CourtListener docket, and Oracle's patch availability document behind the My Oracle Support login. Claims that rest on those are graded through the outlet that relayed them.

| Grade | Meaning in this study |
|---|---|
| Confirmed | Stated in a primary opened for this study: Oracle's alert, the CVE and NVD records, CISA's KEV catalog and alert, the FBI IC3 PSA, the incident responder's own reports (Mandiant/GTIG), the researcher's own disclosure (ZDI), a victim's own statement, HIBP's record, ATT&CK and library data |
| Reported | Journalism, vendor research about cases it did not publish in full, an actor's claims, or a secondary account of a primary that was not opened |
| Demonstrated | Shown by a reproducible check; none in this brief |
| Inferred | This study's reasoning from cited facts, labelled where it appears |

## Part 1: what happened

| Date (2026 unless stated) | Event | Sources | Grade |
|---|---|---|---|
| 1 Apr | Oracle's CNA reserves CVE-2026-35273 | [2] | Confirmed |
| 15 May | FBI IC3 PSA I-051526-PSA warns about ShinyHunters: extortion emails signed ShinyHunters, harassment, sometimes swatting, a Tor leak site, elevated risk for educational institutions; no mention of PeopleSoft | [6] | Confirmed |
| May | Beazley's DFIR team handles a breach later confirmed as part of the PeopleSoft wave | [21] | Reported |
| 27 May | UNC6240 sets up staging infrastructure; zero-day exploitation of PSEMHUB endpoints begins | [7] | Confirmed |
| May and July | Intrusions with MeshAgent persistence and Microsoft-themed domains | [8] | Confirmed |
| June | ShinyHunters says it tried and failed to breach an FBI PeopleSoft database | [17] | Reported |
| 9 Jun | Stolen data published on the ShinyHunters leak site; zero-day window closes; HIBP's breach date for Nottingham | [7] [11] | Confirmed |
| 10 Jun | Oracle Security Alert, Rev 1, for PeopleTools 8.61 and 8.62; ZDI reports its three issues to Oracle the same day | [1] [9] | Confirmed |
| 10 Jun | University of Nottingham statement on student and alumni data, working with Action Fraud and the ICO | [10] | Confirmed |
| 11 Jun | CVE record published 02:25Z; NVD publishes; CISA SSVC: exploitation active | [2] [3] | Confirmed |
| 11 Jun | GTIG report: more than 100 organizations notified, 68% higher education | [7] | Confirmed |
| 11 Jun | Nottingham reported among the first confirmed victims; Mandiant's CTO confirms exploitation in the wild | [13] | Reported |
| 12 Jun | CISA adds the CVE to KEV, due 15 Jun, and issues its alert | [4] [5] | Confirmed |
| 23 Jul | NVD record last modified; status Analyzed as of 11 Nov | [3] | Confirmed |
| 29 Jul | ATT&CK's G1057 ShinyHunters entry carries this created date (v1.0) | [12] | Confirmed |
| September | Renewed n-day mass exploitation; WAF rules bypassed with path encoding | [8] | Confirmed |
| 15 to 16 Sep | Dutch police arrest a 24-year-old in the ShinyHunters investigation (confirmed 28 Sep) | [16] | Reported |
| 22 Sep | FBI jobs site defaced; actor claims data on FBI employees and applicants | [15] | Reported |
| 25 Sep | GTIG publishes the renewed-campaign report | [8] | Confirmed |
| 28 Sep | Krebs reports an FBI statement confirming the jobs-site compromise through CVE-2026-35273 | [16] | Reported |
| 29 Sep to 3 Oct | Jordanian authorities detain an alleged member, reportedly cooperating with the FBI (Risky Bulletin dates it about 29 Sep, Krebs 3 Oct) | [17] [20] | Reported |
| 30 Sep | ShinyHunters leak site goes offline | [17] | Reported |
| 5 Oct | Reuters: more than 5,000 FBI personnel exposed; the FBI drops a contractor that had not patched | [17] [20] | Reported |
| 9 Oct | FBI announces another arrest tied to the FBI jobs incident | [19] | Reported |
| 20 or 27 Oct | ZDI publishes the three-flaw chain (URL path 2026/10/20, page date 27 October) | [9] | Confirmed |
| 10 Nov | KEV catalog 2026.11.10: still the only PeopleSoft entry | [4] | Confirmed |

## Part 2: the technical record

**The flaw.** Oracle's alert covers the Updates Environment Management component of PeopleTools, reachable over HTTP without authentication, rated 9.8, and says exploitation may result in remote code execution [1] (**Confirmed**). NVD and KEV classify it as CWE-306, Missing Authentication for Critical Function as NVD and KEV name it, with CISA ADP as the CWE source [3] [4] (**Confirmed**). ZDI's write-up says the single fix covers three issues: an SSRF in the Integration Gateway (PSIGW), external control of a file path in the Environment Management Hub (PSEMHUB), and deserialization of untrusted data in PSEMHUB, which ZDI tracked as ZDI-CAN-31816, 31818 and 31817 [9] (**Confirmed**). ZDI also describes a host check that trusts localhost [9] (**Confirmed** as ZDI states it). GTIG's September report says both exploitation methods it saw abuse Java deserialization in the PSEMHUB hub servlet [8] (**Confirmed**); the two accounts are complementary (**Inferred**).

**June, the zero-day wave.** GTIG saw exploitation against PSEMHUB endpoints from 27 May to 9 June [7]. After access the actor used MeshCentral 1.1.59 with disguised agents, acme-client to obtain certificates for a masquerading domain, sshpass for SSH lateral movement, zstd to archive data before exfiltration, a custom lateral-movement and defacement script, and a marker file telling victims they had been hacked [7] (**Confirmed**).

**September, the n-day wave.** The actor sent roughly 5 to 15 verification probes per host before exploiting it, then either dropped JSP web shells into the PSEMHUB web application directory, repeating the drop to reach every node behind a load balancer, or ran commands without writing files [8] (**Confirmed**). About a quarter of the observed commands ran as root or SYSTEM [8] (**Confirmed**). Tools named: the JSP web shells, the SIDEEYE C++ backdoor inside a trojanized, EV-signed media-player installer (GTIG asked Sectigo to revoke the certificate), the Neo-reGeorg SOCKS-over-HTTP tunnel and MeshCentral/MeshAgent [8] (**Confirmed**). The bypass worked because proxies and WAFs matched the literal path before decoding while the application server decoded it [8] (**Confirmed**).

**One more incident record.** Sekoia and Beazley describe a May breach later tied to the wave with JSP backdoors, pass-the-hash, Chisel tunnels, scheduled tasks, an EDR-disabling script, MeshAgent command and control and Rclone exfiltration [21] (**Reported**).

## Part 3: who and why

- **Mandiant/GTIG** attribute both waves to UNC6240, which they track as ShinyHunters; the June post states no confidence level [7] [8] (**Confirmed** for what GTIG says).
- **ATT&CK** records ShinyHunters as [G1057](/mitre/groups/G1057.md), aliases UNC6240 and Bling Libra, and maps its CVE-2026-35273 use to T1190 and T1587.004, plus T1083 for checking PeopleSoft configuration files, citing the June GTIG post [12] (**Confirmed**). G1057 associates the group with The Com, whose members include [Scattered Spider (G1015)](/mitre/groups/G1015.md) and [LAPSUS$ (G1004)](/mitre/groups/G1004.md), and notes "Scattered Lapsus Hunters" and "SLSH" as labels in public reporting [12] (**Confirmed**).
- **Neither GTIG post** ties the PeopleSoft activity to Scattered LAPSUS$ Hunters, Cl0p or the Oracle E-Business Suite campaign (**Inferred** from the two posts [7] [8]). This brief makes no such link.
- **The arrests.** Dutch police arrested a 24-year-old [16], Jordanian authorities detained an alleged member [20], and the FBI announced an arrest on 9 October on charges of conspiracy to threaten to impair the confidentiality of information with intent to extort and interference with commerce by threats [19] (**Reported**). No source opened shows any arrested person carried out the PeopleSoft exploitation (**Inferred**).

**Motive.** Data theft for extortion: GTIG describes UNC6240's "well-established pattern of data theft extortion" [8], and the June wave ended in leak-site publication and marker files [7] (**Confirmed**). The FBI intrusion was framed differently, as retaliation for the 15 May PSA [15] (**Reported**). The FBI is quoted as saying ShinyHunters extorted over USD 70 million in 2026, a figure not specific to PeopleSoft [18] (**Reported**).

## Part 4: impact and response

**Universities first.** GTIG's notification list was 68% higher education [7] (**Confirmed**), and the FBI's May PSA had already warned that educational institutions were at elevated risk [6] (**Confirmed**). Nottingham's statement names neither PeopleSoft nor ShinyHunters [10] (**Confirmed**); HIBP links the breach to a ShinyHunters "pay or leak" campaign without naming PeopleSoft [11] (**Confirmed** as HIBP's record); the PeopleSoft link comes from news [13] (**Reported**).

**Other sectors.** The September wave reached higher education, technology, IT services, healthcare, agriculture, transportation and government [8] (**Confirmed**).

**The FBI recruitment site.** An FBI spokesperson told 404 Media the group exploited a PeopleSoft zero-day, pivoted to AWS GovCloud servers and downloaded 2 to 3 TB [15]; Reuters reported more than 5,000 personnel exposed and a contractor dropped for failing to patch [17] [20] (**Reported**).

**Not this campaign.** The Boeing/Jeppesen ForeFlight extortion is not linked to PeopleSoft [17], and Harvard's 2025 breach was phone-based phishing per Harvard [22] (**Reported**). Neither is counted here.

**Government record.** CISA's KEV entry carries a three-day due date and a required action under BOD 26-04 [4], announced in the 12 June alert [5] (**Confirmed**). It is the only PeopleSoft row in KEV; other 2026 Oracle additions were E-Business Suite CVE-2026-46817 (15 July), HTTP Server/WebLogic Proxy Plug-in CVE-2026-21962 (24 August) and WebLogic CVE-2024-21182 (1 June) [4] (**Confirmed**). Nottingham said it was working with Action Fraud and the ICO [10] (**Confirmed**).

## Part 5: the defender and vulnerability-management view

- **Read KEV and SSVC, not just the vendor page.** CISA scored exploitation active the day the CVE published [3] and set a 15 June deadline [4] (**Confirmed**); the vendor alert said nothing about exploitation [1] (**Confirmed**).
- **Close the stopgap.** A WAF exception should carry an expiry date and a patch ticket; September shows what a stopgap left open for three months costs [8] (**Inferred** lesson from **Confirmed** facts).
- **Track the chain, not just the id.** One CVE with CWE-306 understates an SSRF, a path flaw and a deserialization flaw [3] [9] (**Inferred**).
- **Assume prior access.** The zero-day window closed before the fix shipped [1] [7], so every exposed host needed a hunt as well as a patch (**Inferred**).

### What is overstated and what is understated

- *Overstated:* "PeopleSoft zero-days", plural: the record has one CVE, which ZDI says covers three chained issues with separate CVEs pending [1] [9] (**Inferred**). "More than 100 victims" counts organizations GTIG notified, not ones confirmed compromised [7] [15] (**Confirmed** for GTIG's wording). "FBI hacked": the opened record covers the FBI jobs site, a pivot to AWS GovCloud servers described by a spokesperson through 404 Media, and a contractor dropped for not patching [15] [17] [20] (**Reported**); no opened source describes access to other FBI networks (**Inferred**). Extortion totals are not PeopleSoft-specific [18] (**Reported**).
- *Understated:* Oracle's alert is silent on exploitation while KEV, SSVC and GTIG confirm it [1] [3] [4] [7] (**Confirmed**). CWE-306 alone understates the chain [9] (**Inferred**). KEV flags known ransomware-campaign use [4] (**Confirmed**). And the WAF-only mitigation was bypassed, so the patch is the fix [8] (**Confirmed**).

## MITRE mappings

This Part binds the record to ATT&CK v20.0 Enterprise, CWE, CAPEC and D3FEND, with names and tactics from the library's `data/attack/` and `data/weaknesses/` files [23]. No industrial system is involved, so no ATT&CK for ICS technique applies.

### Groups, software and campaigns

| Object | Name | Binding | Sources |
|---|---|---|---|
| [G1057](/mitre/groups/G1057.md) | ShinyHunters | Actor: GTIG attributes both waves to UNC6240, tracked as ShinyHunters; ATT&CK cites the June post | [7] [8] [12] |
| [S1189](/mitre/software/S1189.md) | Neo-reGeorg | SOCKS-over-HTTP tunnel in the September wave | [8] |
| [S1040](/mitre/software/S1040.md) | Rclone | Exfiltration in the Beazley DFIR case (**Reported**) | [21] |
| [C0059](/mitre/campaigns/C0059.md) | Salesforce Data Exfiltration | Context only: ATT&CK's prior record of UNC6240 extortion, which cautions that overlaps are not necessarily a direct operational relationship | [12] [23] |
| [G1015](/mitre/groups/G1015.md), [G1004](/mitre/groups/G1004.md) | Scattered Spider, LAPSUS$ | Context only: named in the G1057 entry as fellow Com members; not bound | [12] |

MeshCentral/MeshAgent, SIDEEYE and Chisel have no ATT&CK software object in the library's `data/attack/software.jsonl` [23], so they are named in the text only.

### ATT&CK Enterprise techniques

| ID | Name | Tactic(s) | Dated event or report | Sources |
|---|---|---|---|---|
| [`T1596.003`](/mitre/techniques/T1596-003.md) | Digital Certificates | Reconnaissance | Listed in GTIG's September report | [8] |
| [`T1596.005`](/mitre/techniques/T1596-005.md) | Scan Databases | Reconnaissance | Listed in GTIG's September report | [8] |
| [`T1595.002`](/mitre/techniques/T1595-002.md) | Vulnerability Scanning | Reconnaissance | 5 to 15 verification probes per host, September | [8] |
| [`T1587.004`](/mitre/techniques/T1587-004.md) | Exploits | Resource Development | ATT&CK G1057 entry for CVE-2026-35273 (June) | [12] |
| [`T1588.004`](/mitre/techniques/T1588-004.md) | Digital Certificates | Resource Development | acme-client certificates for a masquerading domain, June | [7] |
| [`T1190`](/mitre/techniques/T1190.md) | Exploit Public-Facing Application | Initial Access | Zero-day 27 May to 9 Jun; n-day September | [7] [8] [12] |
| [`T1059.003`](/mitre/techniques/T1059-003.md) | Windows Command Shell | Execution | Fileless commands, September | [8] |
| [`T1059.004`](/mitre/techniques/T1059-004.md) | Unix Shell | Execution | Fileless commands, September | [8] |
| [`T1505.003`](/mitre/techniques/T1505-003.md) | Web Shell | Persistence | JSP web shells in PSEMHUB, September; JSP hunting advised in June | [7] [8] |
| [`T1027`](/mitre/techniques/T1027.md) | Obfuscated Files or Information | Stealth | Listed in GTIG's September report | [8] |
| [`T1036.005`](/mitre/techniques/T1036-005.md) | Match Legitimate Resource Name or Location | Stealth | Disguised MeshCentral agents, June | [7] |
| [`T1553.002`](/mitre/techniques/T1553-002.md) | Code Signing | Defense Impairment | SIDEEYE in an EV-signed installer, September | [8] |
| [`T1082`](/mitre/techniques/T1082.md) | System Information Discovery | Discovery | Listed in GTIG's September report | [8] |
| [`T1016`](/mitre/techniques/T1016.md) | System Network Configuration Discovery | Discovery | Listed in GTIG's September report | [8] |
| [`T1083`](/mitre/techniques/T1083.md) | File and Directory Discovery | Discovery | Checking PeopleSoft configuration files (ATT&CK G1057) | [12] |
| [`T1552.001`](/mitre/techniques/T1552-001.md) | Credentials In Files | Credential Access | Listed in GTIG's September report | [8] |
| [`T1021.004`](/mitre/techniques/T1021-004.md) | SSH | Lateral Movement | sshpass for SSH lateral movement, June | [7] |
| [`T1560.001`](/mitre/techniques/T1560-001.md) | Archive via Utility | Collection | zstd archives before exfiltration, June | [7] |
| [`T1090`](/mitre/techniques/T1090.md) | Proxy | Command and Control | Neo-reGeorg, September | [8] |
| [`T1219`](/mitre/techniques/T1219.md) | Remote Access Tools | Command and Control | MeshCentral 1.1.59, June; MeshAgent May, July, September | [7] [8] |
| [`T1048`](/mitre/techniques/T1048.md) | Exfiltration Over Alternative Protocol | Exfiltration | Listed in GTIG's September report | [8] |
| [`T1657`](/mitre/techniques/T1657.md) | Financial Theft | Impact | Leak-site publication and victim marker file, 9 June | [7] [8] [12] |
| [`T1491.002`](/mitre/techniques/T1491-002.md) | External Defacement | Impact | FBI jobs site defaced, 22 Sep (**Reported**) | [15] |
| [`T1550.002`](/mitre/techniques/T1550-002.md) | Pass the Hash | Lateral Movement | Beazley DFIR case, May (**Reported**) | [21] |
| [`T1572`](/mitre/techniques/T1572.md) | Protocol Tunneling | Command and Control | Chisel tunnels, Beazley case (**Reported**) | [21] |
| [`T1053.005`](/mitre/techniques/T1053-005.md) | Scheduled Task | Execution, Persistence, Privilege Escalation | Beazley case (**Reported**) | [21] |
| [`T1685`](/mitre/techniques/T1685.md) | Disable or Modify Tools | Defense Impairment | EDR-disabling script, Beazley case (**Reported**) | [21] |

Fit notes (**Inferred**): the fourteen ids GTIG lists are bound as GTIG lists them; reading T1027 as the encoded path is this study's inference. T1588.004, T1036.005, T1021.004 and T1560.001 rest on the tools GTIG names in June. T1657 covers extortion through leak-site publication. T1491.002 rests on news. Left out: T1491.001 Internal Defacement (ATT&CK lists it for G1057, but the record does not say where the defacement script ran) and T1567.002 (the Beazley case names Rclone, not a destination).

### CWE and CAPEC

[CWE-306](/CWE_REFERENCE.md), Missing Authentication for Critical Function as NVD and KEV name it, is the only CWE in the CVE, NVD and KEV records [3] [4] (**Confirmed**). Mapping ZDI's three classes gives CWE-918 Server-Side Request Forgery, CWE-73 External Control of File Name or Path and CWE-502 Deserialization of Untrusted Data [9] [23] (**Inferred**).

| CAPEC | Name | Via | Where it meets the record |
|---|---|---|---|
| [CAPEC-36](/mitre/capec/CAPEC-36.md) | Using Unpublished Interfaces or Functionality | CWE-306 | An unauthenticated management hub reachable over HTTP [1] [7] |
| [CAPEC-664](/mitre/capec/CAPEC-664.md) | Server Side Request Forgery | CWE-918 | SSRF in PSIGW [9] |
| [CAPEC-76](/mitre/capec/CAPEC-76.md) | Manipulating Web Input to File System Calls | CWE-73 | File-path control in PSEMHUB [9] |
| [CAPEC-586](/mitre/capec/CAPEC-586.md) | Object Injection | CWE-502 | Deserialization in PSEMHUB [8] [9] |
| [CAPEC-72](/mitre/capec/CAPEC-72.md) | URL Encoding | CWE-177, CWE-173 (in the filtering rule, not PeopleSoft) | Encoded path past WAF rules, September [8] |
| [CAPEC-267](/mitre/capec/CAPEC-267.md) | Leverage Alternate Encoding | CWE-173, T1027 | Parent pattern of the September bypass [8] |

Each fit is **Inferred**; the CAPEC-to-CWE links are the library's [23].

### D3FEND countermeasures

The library maps these D3FEND techniques to the study's techniques, and the record calls for each [23]: [Inbound Traffic Filtering](/mitre/d3fend/inbound-traffic-filtering.md) and [Network Traffic Filtering](/mitre/d3fend/network-traffic-filtering.md) for T1190 (block external access to the PSEMHUB and listening-connector paths [7]); [File Integrity Monitoring](/mitre/d3fend/file-integrity-monitoring.md) for T1505.003 (unexpected JSP, JSPX and EXE files [7] [8]); [Process Spawn Analysis](/mitre/d3fend/process-spawn-analysis.md) and [Process Lineage Analysis](/mitre/d3fend/process-lineage-analysis.md) for T1505.003 (shells spawned by the WebLogic Java process [8]); and [Outbound Traffic Filtering](/mitre/d3fend/outbound-traffic-filtering.md) for T1219 and T1572 (egress monitoring and outbound SMB [7] [8]). [Software Update](/mitre/d3fend/software-update.md) is the fix itself; the library's mapping does not tie it to T1190 (**Inferred** for each fit).

### Navigator layer

The study's Navigator layer is [`navigator/library-layers/oracle-peoplesoft-shinyhunters-2026.json`](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/oracle-peoplesoft-shinyhunters-2026.json) ([open in Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/library-layers/oracle-peoplesoft-shinyhunters-2026.json)), listed on [the Navigator layers page](/navigator/index.md). Scores: 100 where a primary states the behavior and the fit is direct, 60 where the fit is partly inferred, 40 where only a Reported source supports it; each comment names its source numbers.

## Cross-cutting themes

- **Mass exploitation, then a leak site.** Like [the Cl0p file-transfer breaches](/case-studies/CL0P_FILE_TRANSFER_2023.md), one flaw in an application that holds bulk records fed a data-theft extortion campaign. The lineage is by pattern, not actor (**Inferred**).
- **Zero-day before the vendor alert, KEV within days.** [SharePoint ToolShell 2025](/case-studies/SHAREPOINT_TOOLSHELL_2025.md) followed the same arc, and [PHP2Shell October 2026](/case-studies/PHP2SHELL_OCTOBER_2026.md) shares its first half, exploitation before public disclosure (**Inferred**).
- **Education as a soft target.** The May PSA, issued after an attack on a learning-management system disrupted schools [6] (the PSA names no platform; [the Instructure Canvas breach study](/case-studies/INSTRUCTURE_CANVAS_BREACH_2026.md) is the home study for the Canvas extortion of that month), and the June notification list [7] both point at schools (**Inferred**).
- **Careful attribution.** ATT&CK associates G1057 with The Com but cautions in C0059 that overlaps are not necessarily a direct operational relationship [12] (**Confirmed**), and the group itself denied being part of The Com [15] (**Reported**). As at [Change Healthcare](/case-studies/CHANGE_HEALTHCARE_2024.md), where the first filing's nation-state attribution was withdrawn, early labels deserve caution (**Inferred**).

## Sources

All sources were opened on 11 November 2026.

| # | Source | URL | Opened | Grade |
|---|---|---|---|---|
| 1 | Oracle, Security Alert Advisory CVE-2026-35273, Rev 1, 10 Jun 2026 | [oracle.com/security-alerts/alert-cve-2026-35273.html](https://www.oracle.com/security-alerts/alert-cve-2026-35273.html) | 2026-11-11 | Confirmed |
| 2 | CVE.org record CVE-2026-35273 (CVE Services API) | [cveawg.mitre.org/api/cve/CVE-2026-35273](https://cveawg.mitre.org/api/cve/CVE-2026-35273) | 2026-11-11 | Confirmed |
| 3 | NVD CVE API, CVE-2026-35273 | [services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-35273](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-35273) | 2026-11-11 | Confirmed |
| 4 | CISA, Known Exploited Vulnerabilities catalog JSON, version 2026.11.10 | [cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) | 2026-11-11 | Confirmed |
| 5 | CISA, CISA Adds One Known Exploited Vulnerability to Catalog, 12 Jun 2026 | [cisa.gov/news-events/alerts/2026/06/12/...](https://www.cisa.gov/news-events/alerts/2026/06/12/cisa-adds-one-known-exploited-vulnerability-catalog) | 2026-11-11 | Confirmed |
| 6 | FBI IC3, PSA I-051526-PSA, ShinyHunters, 15 May 2026 | [ic3.gov/PSA/2026/PSA260515](https://www.ic3.gov/PSA/2026/PSA260515) | 2026-11-11 | Confirmed |
| 7 | Mandiant/GTIG, ShinyHunters Targets Education Sector with Oracle PeopleSoft Exploit, 11 Jun 2026 | [cloud.google.com/blog/topics/threat-intelligence/shinyhunters-targets-education-sector-oracle-exploit](https://cloud.google.com/blog/topics/threat-intelligence/shinyhunters-targets-education-sector-oracle-exploit) | 2026-11-11 | Confirmed |
| 8 | Mandiant/GTIG, ShinyHunters Renewed Mass Exploitation Campaign Targeting Oracle PeopleSoft, 25 Sep 2026 | [cloud.google.com/blog/topics/threat-intelligence/shinyhunters-renewed-mass-exploitation-...](https://cloud.google.com/blog/topics/threat-intelligence/shinyhunters-renewed-mass-exploitation-campaign-targeting-oracle-peoplesoft/) | 2026-11-11 | Confirmed |
| 9 | TrendAI Zero Day Initiative, CVE-2026-35273: SSRF to RCE in Oracle PeopleSoft (page dated 27 Oct 2026) | [zerodayinitiative.com/blog/2026/10/20/...](https://www.zerodayinitiative.com/blog/2026/10/20/cve-2026-35273-ssrf-to-rce-in-oracle-peoplesoft) | 2026-11-11 | Confirmed |
| 10 | University of Nottingham, student and alumni data compromised in a data security incident, 10 Jun 2026 | [nottingham.ac.uk/currentstudents/news/...](https://www.nottingham.ac.uk/currentstudents/news/student-and-alumni-data-has-been-compromised-in-a-data-security-incident) | 2026-11-11 | Confirmed |
| 11 | Have I Been Pwned, breach record UniversityOfNottingham | [haveibeenpwned.com/api/v3/breach/UniversityOfNottingham](https://haveibeenpwned.com/api/v3/breach/UniversityOfNottingham) | 2026-11-11 | Confirmed |
| 12 | MITRE ATT&CK, Group G1057 ShinyHunters | [attack.mitre.org/groups/G1057/](https://attack.mitre.org/groups/G1057/) | 2026-11-11 | Confirmed |
| 13 | The Hacker News, ShinyHunters exploits Oracle PeopleSoft, 11 Jun 2026 | [thehackernews.com/2026/06/shinyhunters-exploits-oracle-peoplesoft.html](https://thehackernews.com/2026/06/shinyhunters-exploits-oracle-peoplesoft.html) | 2026-11-11 | Reported |
| 14 | The Hacker News, ShinyHunters-exploited Oracle PeopleSoft zero-day turns out to be three chained flaws, 28 Oct 2026 | [thehackernews.com/2026/10/shinyhunters-exploited-oracle.html](https://thehackernews.com/2026/10/shinyhunters-exploited-oracle.html) | 2026-11-11 | Reported |
| 15 | Infosecurity Magazine, ShinyHunters claims FBI hack via PeopleSoft zero day, 23 Sep 2026 | [infosecurity-magazine.com/news/shinyhunters-fbi-hack-peoplesoft/](https://www.infosecurity-magazine.com/news/shinyhunters-fbi-hack-peoplesoft/) | 2026-11-11 | Reported |
| 16 | Krebs on Security, Dutch police arrest reformed hacker in ShinyHunters investigation, 28 Sep 2026 | [krebsonsecurity.com/2026/09/...](https://krebsonsecurity.com/2026/09/dutch-police-arrest-reformed-hacker-in-shiny-hunters-investigation/) | 2026-11-11 | Reported |
| 17 | Krebs on Security, ShinyHunters extorted Boeing spin-off prior to arrests, 7 Oct 2026 | [krebsonsecurity.com/2026/10/...](https://krebsonsecurity.com/2026/10/shinyhunters-extorted-boeing-spin-off-prior-to-arrests/) | 2026-11-11 | Reported |
| 18 | Krebs on Security, Feds suspect ransom negotiator ran ShinyHunters extortion site, 19 Oct 2026 | [krebsonsecurity.com/2026/10/...](https://krebsonsecurity.com/2026/10/feds-suspect-ransom-negotiator-ran-shinyhunters-extortion-site/) | 2026-11-11 | Reported |
| 19 | Infosecurity Magazine, net closes on ShinyHunters with another arrest, 12 Oct 2026 | [infosecurity-magazine.com/news/net-closes-shinyhunters-another/](https://www.infosecurity-magazine.com/news/net-closes-shinyhunters-another/) | 2026-11-11 | Reported |
| 20 | Risky Bulletin, ShinyHunters suspects arrested in US and Jordan, 12 Oct 2026 | [risky.biz/risky-bulletin-shinyhunters-suspects-arrested-in-us-and-jordan/](https://risky.biz/risky-bulletin-shinyhunters-suspects-arrested-in-us-and-jordan/) | 2026-11-11 | Reported |
| 21 | Sekoia TDR and Beazley Security, Gotta Breach 'Em All: the journey of ShinyHunters, 1 Oct 2026 | [sekoia.com/blog/gotta-breach-em-all-the-journey-of-shinyhunters](https://www.sekoia.com/blog/gotta-breach-em-all-the-journey-of-shinyhunters) | 2026-11-11 | Reported |
| 22 | The Register, ShinyHunters hit Harvard alumni, donors and students, 3 Nov 2026 | [theregister.com/cyber-crime/2026/11/03/...](https://www.theregister.com/cyber-crime/2026/11/03/shinyhunters-hit-850k-alumni-donors-students-and-fam-in-last-years-harvard-university-raid/5307272) | 2026-11-11 | Reported |
| 23 | TeamStarWolf library data: `data/attack/technique_profiles.jsonl`, `groups.jsonl`, `group_to_technique.jsonl`, `campaigns.jsonl`, `software.jsonl`, `technique_to_d3fend.jsonl`, `data/weaknesses/cwe.jsonl`, `capec.jsonl` and the `mitre/` tree | [github.com/TeamStarWolf/TeamStarWolf/tree/main/data](https://github.com/TeamStarWolf/TeamStarWolf/tree/main/data) | 2026-11-11 | Confirmed |

*© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.*

*© The MITRE Corporation. Includes material from the Common Weakness Enumeration (CWE™), used under the CWE Terms of Use. https://cwe.mitre.org/*

*© The MITRE Corporation. Includes material from the Common Attack Pattern Enumeration and Classification (CAPEC™), used under the CAPEC Terms of Use. https://capec.mitre.org/*

*© The MITRE Corporation. Includes material from MITRE D3FEND™, used under the D3FEND Terms of Use. https://d3fend.mitre.org/*

*The terms for every MITRE dataset used here are recorded in [THIRD_PARTY_NOTICES.md](/THIRD_PARTY_NOTICES.md).*

## Related references

- [The Year 2026 in Intrusions](/case-studies/CHRONICLE_2026.md), [The Instructure Canvas Breach and ShinyHunters Extortion of 2026](/case-studies/INSTRUCTURE_CANVAS_BREACH_2026.md)
- [The Cl0p File-Transfer Breaches](/case-studies/CL0P_FILE_TRANSFER_2023.md), [Change Healthcare 2024](/case-studies/CHANGE_HEALTHCARE_2024.md), [SharePoint ToolShell 2025](/case-studies/SHAREPOINT_TOOLSHELL_2025.md), [PHP2Shell October 2026](/case-studies/PHP2SHELL_OCTOBER_2026.md), [Log4Shell](/case-studies/LOG4SHELL.md)
- [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [Notable Incidents](/NOTABLE_INCIDENTS.md)
- [CVE Reference](/CVE_REFERENCE.md), [CWE Reference](/CWE_REFERENCE.md), [CAPEC Reference](/CAPEC_REFERENCE.md), [D3FEND Reference](/D3FEND_REFERENCE.md)
- [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [Vulnerability Prioritization Reference](/VULNERABILITY_PRIORITIZATION_REFERENCE.md), [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md), [Threat Intelligence Reference](/THREAT_INTELLIGENCE_REFERENCE.md), [Data Security Reference](/DATA_SECURITY_REFERENCE.md)
- Groups, software and campaigns: [G1057 ShinyHunters](/mitre/groups/G1057.md), [G1015 Scattered Spider](/mitre/groups/G1015.md), [G1004 LAPSUS$](/mitre/groups/G1004.md), [S1189 Neo-reGeorg](/mitre/software/S1189.md), [S1040 Rclone](/mitre/software/S1040.md), [C0059 Salesforce Data Exfiltration](/mitre/campaigns/C0059.md)
- Techniques: [T1190 Exploit Public-Facing Application](/mitre/techniques/T1190.md), [T1505.003 Web Shell](/mitre/techniques/T1505-003.md), [T1219 Remote Access Tools](/mitre/techniques/T1219.md), [T1090 Proxy](/mitre/techniques/T1090.md), [T1587.004 Exploits](/mitre/techniques/T1587-004.md), [T1552.001 Credentials In Files](/mitre/techniques/T1552-001.md), [T1048 Exfiltration Over Alternative Protocol](/mitre/techniques/T1048.md), [T1657 Financial Theft](/mitre/techniques/T1657.md)
- CAPEC: [CAPEC-36](/mitre/capec/CAPEC-36.md), [CAPEC-664](/mitre/capec/CAPEC-664.md), [CAPEC-76](/mitre/capec/CAPEC-76.md), [CAPEC-586](/mitre/capec/CAPEC-586.md), [CAPEC-72](/mitre/capec/CAPEC-72.md), [CAPEC-267](/mitre/capec/CAPEC-267.md)
- [Navigator layers](/navigator/index.md), including this study's layer, [oracle-peoplesoft-shinyhunters-2026.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/oracle-peoplesoft-shinyhunters-2026.json)
- The [Team Star Wolf Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/)
- [All case studies](/case-studies/README.md)
