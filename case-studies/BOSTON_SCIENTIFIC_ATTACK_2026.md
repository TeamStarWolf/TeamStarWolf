# The Boston Scientific Network Outage of August 2026: A Case Study

*A TeamStarWolf case study. Published 11 November 2026; every source checked as of that date.*

[All case studies](/case-studies/README.md) · Related: [The Year 2026 in Intrusions](/case-studies/CHRONICLE_2026.md), [The Stryker Device-Wipe Attack of March 2026](/case-studies/STRYKER_HANDALA_WIPER_2026.md), [Healthcare Threat Actor Watchlist](/case-studies/HEALTHCARE_THREAT_WATCHLIST.md), [Change Healthcare 2024](/case-studies/CHANGE_HEALTHCARE_2024.md), [Notable Incidents](/NOTABLE_INCIDENTS.md), [Healthcare Security Reference](/HEALTHCARE_SECURITY_REFERENCE.md), [Edge Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Medical-technology and manufacturing security teams, network and edge-device owners, incident responders, business continuity leads and vulnerability management leads

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 16 min (3,612 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want the dated record of the August 2026 Boston Scientific outage, what the CrowdStrike summary found and did not find, or which edge-device, segmentation and continuity controls the case argues for

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [Part 1: what happened](#part-1-what-happened), [Part 5: the defender and vulnerability-management view](#part-5-the-defender-and-vulnerability-management-view)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Edge Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md), [Healthcare Security Reference](/HEALTHCARE_SECURITY_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md), [The Year 2026 in Intrusions](/case-studies/CHRONICLE_2026.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive summary

From 25 August 2026 Boston Scientific could not process or ship customer orders until shipping returned for most products on 3 September, with full restoration on 9 September [4] [8] [11] (**Confirmed**). New cardiac remote-monitoring activations stopped until 8 September: new communicators could not be activated and new insertable cardiac monitors could not pair with the patient phone app, so clinics retrieved episodes in person [4] [15] (**Confirmed**). Implanted device function was not affected [4] [5] (**Confirmed**). The company's chief executive later said every plant and distribution center had been shut and that some procedures were lost to hospital supply shortfalls [24] (**Reported**).

CrowdStrike, the company's responder, found that an unauthorized third party got in through an external-facing network management device and reached only part of the on-premises IT environment; it found no evidence of encryption, of activity after 25 August, of actor activity in Microsoft 365, of interactive remote access to SCADA, manufacturing or medical device systems, or of authentication to cloud applications [13] (**Confirmed**). No device vendor, model, CVE, threat actor or extortion claim appears in the sources opened for this study [12] [13] [20] [22] (**Inferred** from absence). Even so, the company told the SEC on 8 September that the incident was likely to be material to its third-quarter and full-year results [14] (**Confirmed**).

### Key facts at a glance

| Field | Value |
|---|---|
| Victim | Boston Scientific Corporation (NYSE: BSX), Marlborough, Massachusetts; global medical technology company [17] (**Confirmed**) |
| Identified | 25 August 2026; containment began the same day [1] [11] [13] (**Confirmed**) |
| Way in | An external-facing network management device; vendor, model and CVE not named [12] [13] (**Confirmed**) |
| Reach | A limited portion of the on-premises IT environment; cloud systems not affected [6] [13] (**Confirmed**) |
| Not found | Encryption, data staging or exfiltration from the reviewed systems, activity after 25 August [13] (**Confirmed**, scoped to the systems reviewed) |
| Named actor | None; the company refers only to "the threat actor" [12] (**Confirmed**); no group claimed it as of 26 August [22] (**Reported**) |
| CVE and KEV | None tied to the incident; KEV catalog 2026.11.10 has no row naming the company [20] (**Inferred**) |
| Outage | 25 August to 9 September for manufacturing, order fulfillment and shipping [11] (**Confirmed**) |
| Financial effect | Material to Q3 2026; idle production time cut Q3 gross margin by 1.7 points; no dollar cost disclosed [14] [18] (**Confirmed**) |

### Key findings

- **One edge device, up to two weeks of disrupted production.** The only stated entry point is an external-facing network management device [13], and the 8-K says the unauthorized activity caused a network outage that cut manufacturing, order processing and shipping [14] (**Confirmed**). Nothing in the record says the actor encrypted or destroyed anything [13] (**Confirmed**).
- **The blast radius stayed on premises.** Microsoft 365, cloud and SaaS applications, SOX financial systems, SCADA and device-maintenance environments showed no evidence of actor access [13] (**Confirmed**); that long list of clean environments is the strongest evidence that separation between environments held the line (**Inferred**).
- **The most useful fact is missing.** Peers cannot check their own exposure: the device's vendor, model and any vulnerability are not public [13] [20] (**Inferred** from absence).
- **Patient services shared the outage.** New remote-monitoring activations for cardiac devices were impaired from 25 August until 8 September [4] [15] (**Confirmed**); that they depended on the affected on-premises network is this study's reading (**Inferred**).

### Top recommendations

1. Take network management interfaces off the internet, or restrict them to a management network, and inventory every external-facing appliance as a tier-zero asset (**Inferred** from [13]; see [M1035](/mitre/mitigations/M1035.md) and [M1042](/mitre/mitigations/M1042.md)).
2. Patch external-facing devices on a KEV clock and hunt for footholds after patching, as the library's watchlist advises [28] (**Inferred**).
3. Keep manufacturing, order processing and patient-service systems in separate trust zones from general IT, and test that an edge foothold cannot reach them ([M1030](/mitre/mitigations/M1030.md); **Inferred** from [13] [14]).
4. Rehearse order-to-ship continuity, including electronic order queuing and controlled manual processes, which the 10-Q flags as a data-integrity risk [4] [18] (**Inferred**).

## Scope and method

This brief covers the incident Boston Scientific identified on 25 August 2026, the recovery, and the disclosures through the third-quarter 10-Q filed on 2 November 2026. It rests on the company's SEC filings, its dated incident updates, CrowdStrike's investigation summary as published by the company, the CISA KEV catalog and trade press. [The Year 2026 in Intrusions](/case-studies/CHRONICLE_2026.md) records the incident in its timeline; this brief is the home study for it. No indicators appear here. Not checked: CISA, FBI, HHS or FDA advisories beyond the KEV catalog, leak sites, the investor-conference recording and the earnings-call transcript.

| Grade | Meaning in this study |
|---|---|
| Confirmed | Stated in a primary opened for this study: an SEC filing, a company update or customer notice, the CrowdStrike summary the company published, the KEV feed, the Intelligence Hub feed or library data; a responder's finding is Confirmed as that responder's finding |
| Reported | Known through journalism or a secondary account of a statement not opened (an analyst note, a conference remark) |
| Inferred | This study's own reasoning from cited facts, including conclusions drawn from absence, labelled where it appears |

## Part 1: what happened

| Date (2026) | Event | Sources | Grade |
|---|---|---|---|
| 29 Jul | Pre-incident guidance: Q3 growth 3 to 5%, adjusted EPS $0.80 to $0.82; full-year reported growth 5.5 to 6.5%, adjusted EPS $3.28 to $3.32 | [16] | Confirmed |
| 25 Aug | System availability issues found on certain network segments, later traced to an unauthorized third party; incident response activated, containment begun, CrowdStrike investigation starts | [1] [13] | Confirmed |
| 26 Aug | Form 8-K under Item 8.01 (Other Events): global disruption including the ability to process and ship orders; materiality not yet determined | [1] [2] | Confirmed |
| 27 Aug | Orders taken through EDI and queued; implanted device function unaffected; new remote-monitoring activations impaired | [4] | Confirmed |
| 29 Aug | CrowdStrike named as responder; cloud systems not affected; manufacturing also impacted | [6] | Confirmed |
| 30 Aug | No unauthorized activity seen since 25 August; working toward partial restoration of shipping for some products that week | [7] | Confirmed |
| 3 Sep | "Growing confidence" access was limited to select internal-facing IT infrastructure; shipping restored for most products at major distribution centers | [8] | Confirmed |
| 5 Sep | Distribution substantially restored at or above normal levels; all sterilization facilities operational; manufacturing resumed at most facilities | [9] | Confirmed |
| 7 to 8 Sep | Form 8-K under Item 1.05 (Material Cybersecurity Incidents), report date 7 September, filed 8 September: likely material to Q3 and FY2026 results; July guidance unlikely to be met; no evidence of ongoing access | [2] [14] | Confirmed |
| 8 Sep | Remote-monitoring activation restored for LATITUDE NXT communicators and LATITUDE Clarity ICMs | [10] [15] | Confirmed |
| 9 Sep | Manufacturing, order fulfillment and shipping fully restored; some business applications still being restored | [11] | Confirmed |
| 28 Oct | Q3 results: net sales $5.138 billion (+1.5%); GAAP EPS $0.40 against $0.51; adjusted EPS $0.73 against $0.75; Q4 sales guided down about 1 to 3% | [17] | Confirmed |
| 2 Nov | Q3 10-Q: material effect on Q3; 1.7-point gross margin hit; civil legal claims filed | [18] | Confirmed |

## Part 2: the intrusion record

CrowdStrike's three-page summary is the only technical primary; its investigation ran from 25 August to 18 September [13] (**Confirmed**). The actor got in through an external-facing network management device and then reached a portion of the on-premises environment [13] (**Confirmed**). How the device was compromised (an exploited flaw, a weak or stolen credential, an exposed management service) is not stated (**Inferred** from absence).

The data finding is scoped. The company's relay says CrowdStrike found no evidence the actor accessed, staged or exfiltrated data from "those systems and applications" [12] (**Confirmed** wording). Neither text clears the on-premises segment the actor reached (**Inferred**). The company's FAQ said it would notify individuals, regulators and customers if personal data were found compromised [8] (**Confirmed**, conditional).

Containment, as Boston Scientific reported it to CrowdStrike and the summary records it: the entry device was disconnected and decommissioned, actor IP addresses and domains were blocked at the firewall, passwords were reset and the environment was hardened, and Falcon coverage was expanded with OverWatch and Active Defense monitoring continuing [13] (**Confirmed** as the company's account).

The outage mechanism is the open question. The Item 1.05 filing says the unauthorized activity caused a network outage affecting access to the systems behind manufacturing, order processing and shipping [14] (**Confirmed**). It does not say whether the actor's actions took systems down or whether defensive isolation did (**Inferred** from absence).

## Part 3: who and why

No one is named. None of the company's filings or updates names a threat actor, group, ransomware brand, ransom demand or leak-site claim; the company's updates speak only of "the threat actor" [12], and its filings of "unauthorized activity" [14] (**Confirmed** as wording; **Inferred** as absence). BleepingComputer found no extortion or ransomware group claiming the attack as of 26 August [22], and MedTech Dive's 2026 roundup names no actor [25] (**Reported**).

The motive is unknown. With no evidence of encryption [13] and no extortion claim on record [22], reading this as ransomware goes beyond the evidence (**Inferred**).

## Part 4: impact and response

**The company.** The outage hit manufacturing as well as order processing and shipping [6] [14] (**Confirmed**). Customers could still submit orders through EDI, later also local applications, into a queue, and email and normal channels with staff kept working [4] [7] (**Confirmed**). The company published no incident press release; disclosure ran through SEC filings and a dedicated update page whose dated archives run from 26 August to 9 September, with a final update on 22 September [12] [19] (**Confirmed**).

**Patients and hospitals.** Monitoring of devices already enrolled and programmer interrogations were unaffected [4] [5] (**Confirmed**). The company said there was no known impact to devices not connected to its network and no evidence the affected network raised cybersecurity risk to hospital networks [5] [8] (**Confirmed** as the company states).

**The money.** Q3 net sales rose 1.5% to $5.138 billion against guidance of 3 to 5%, and adjusted EPS of $0.73 missed the guided $0.80 to $0.82 [16] [17] (**Confirmed**; the comparison is **Inferred**). Full-year guidance fell to about 4.25% reported growth and adjusted EPS of $3.16 to $3.18 [17] (**Confirmed**). The company also cites electrophysiology competition and slower LAAC growth, so attributing the whole gap to the incident would overreach [17] (**Inferred**). The 10-Q blames the Q3 net income decline mainly on incident-driven disruption and idle-production costs, plus litigation charges, and gives no dollar figure [18] (**Confirmed**). J.P. Morgan said the company was less able than Stryker to recapture lost sales [23] (**Reported**).

**Regulators, government and courts.** The Item 1.05 filing said no long-term material impact on financial condition was expected [14] (**Confirmed**). The 10-Q says civil legal claims have been filed, the company may face regulatory scrutiny, and the manual processes used during the response may increase the risk of errors, delays or data-integrity issues; management still concluded disclosure controls were effective as of 30 September [18] (**Confirmed**). No CVE, KEV entry, or CISA, FBI, HHS or FDA advisory about the incident appears in the sources opened [20] [21] (**Inferred**). The Intelligence Hub feed has no row for the incident [21] (**Confirmed**).

**The sector.** Stryker identified a global disruption to its Microsoft environment on 11 March 2026 and reported no indication of ransomware or malware at filing [26], and found it material to Q1 results [27] (**Confirmed**); [The Stryker Device-Wipe Attack of March 2026](/case-studies/STRYKER_HANDALA_WIPER_2026.md) is the home study for that incident. MedTech Dive's 2026 list names nine other medtech victims and describes weeks-long operational shutdowns at Boston Scientific and Stryker [25] (**Reported**). The earlier sector-wide precedent is [Change Healthcare 2024](/case-studies/CHANGE_HEALTHCARE_2024.md) [29] (**Inferred** as lineage).

## Part 5: the defender and vulnerability-management view

- **A CVE queue would not have flagged this.** No CVE or KEV row is attached [20] (**Inferred**). The exposure that mattered was an external-facing management interface, which an asset and attack-surface inventory finds and a CVE queue does not (**Inferred**).
- **Containment was fast; recovery was not.** Containment began on the day of detection [1] [13], yet shipping for most products took 9 days and full restoration 15 [8] [11] (**Confirmed** for the dates; **Inferred** for the reading). Recovery of on-premises business systems is where the cost landed (**Inferred**).
- **Plan the manual processes.** The 10-Q names manual processes as a controls risk [18] (**Confirmed**); defining them before an incident is cheaper than auditing them after (**Inferred**).

### What is overstated and what is understated

- *Overstated:* "global disruption" [1] reads like an enterprise-wide compromise, but the forensic summary confines the actor to part of on-premises IT, with no evidence of cloud, Microsoft 365, SCADA or manufacturing-system access [13] (**Inferred** from [1] [13]). Calling it ransomware, or naming a group, has no support [13] [22] (**Inferred**). The "no exfiltration" reassurance is narrower than it sounds: it covers the systems reviewed, not explicitly the segment the actor reached [12] [13] (**Inferred**).
- *Understated:* a single external-facing device preceded up to two weeks of disrupted manufacturing and shipping and a material quarter without encryption or confirmed exfiltration [11] [13] [18] (**Inferred**). The patient-facing effect, stalled cardiac monitor activations and lost procedures, sits in customer notices and conference remarks rather than the filings [15] [24] (**Confirmed** and **Reported** respectively); its absence from the 8-K and 10-Q is **Inferred** from [14] [18]. And the device's vendor and vulnerability stay undisclosed, so the rest of the sector cannot act on the lesson directly [13] [20] (**Inferred**).

## MITRE mappings

This Part binds the verified record to ATT&CK v20.0 Enterprise, CAPEC and D3FEND, with names and tactics from the library's data files [30] (**Confirmed**). The record states only an initial-access route and an impact, so no row reaches a direct fit (**Inferred**).

### Groups, software and campaigns

No group, software or campaign is bound. No source names an actor, tool or malware family [12] [22] [25] (**Inferred** from absence).

### ATT&CK Enterprise techniques

| ID | Name | Tactic(s) | Dated event or report | Sources | Fit |
|---|---|---|---|---|---|
| [`T1190`](/mitre/techniques/T1190.md) | Exploit Public-Facing Application | Initial Access | Entry through an external-facing network management device, CrowdStrike summary 22 Sep 2026 | [13] | Candidate: the method is not stated |
| [`T1133`](/mitre/techniques/T1133.md) | External Remote Services | Initial Access, Persistence | Same entry, if the device's remote management service was used with valid access | [13] | Candidate: the method is not stated |

Fit notes (**Inferred**): the record supports Initial Access through an external-facing device but not which technique, so both candidates appear at the lowest score in the layer and neither is asserted. Left out: [`T1486`](/mitre/techniques/T1486.md) Data Encrypted for Impact (no evidence of encryption [13]); Valid Accounts (T1078), since password resets are routine containment [13]; Acquire Infrastructure (T1583), because blocked "IP addresses and domains used by the Threat Actor" do not say whether the infrastructure was acquired or compromised [13]; collection, exfiltration and lateral-movement techniques, whose method is not stated [13]; and Impact techniques, because the 8-K describes the outage's effect, not its method [14].

**ATT&CK for ICS:** none. CrowdStrike found no evidence of interactive remote access to SCADA or manufacturing and maintenance systems [13] (**Confirmed**).

### CWE and CAPEC

No CVE is tied to the incident, so no CWE is bound [20] (**Inferred**). The library maps one CAPEC entry to a candidate technique [30] (**Confirmed**):

| CAPEC | Name | Via | Where it meets the record |
|---|---|---|---|
| [CAPEC-555](/mitre/capec/CAPEC-555.md) | Remote Services with Stolen Credentials | T1133 | Applies only if the device was reached with stolen credentials, which the record does not state [13] (**Inferred**, candidate) |

The library maps no CAPEC entry to T1190.

### D3FEND countermeasures

| D3FEND countermeasure | Techniques the library maps it to (from this study) | Where it meets the record |
|---|---|---|
| [Inbound Traffic Filtering](/mitre/d3fend/inbound-traffic-filtering.md) (D3-ITF) | T1190 | Actor IPs and domains blocked at the firewall [13] |
| [Network Traffic Filtering](/mitre/d3fend/network-traffic-filtering.md) (D3-NTF) | T1190 | The same firewall blocks [13] |
| [Session Termination](/mitre/d3fend/session-termination.md) (D3-ST) | T1133 | Entry device disconnected and decommissioned [13] (**Inferred**, partial fit) |

[Credential Rotation](/mitre/d3fend/credential-rotation.md) (D3-CRO), [Password Rotation](/mitre/d3fend/password-rotation.md) (D3-PR) and [Outbound Traffic Filtering](/mitre/d3fend/outbound-traffic-filtering.md) (D3-OTF) also fit the containment steps [13], though the library does not map them to this study's techniques (**Inferred**).

### Navigator layer

The study's Navigator layer is [`navigator/library-layers/boston-scientific-attack-2026.json`](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/boston-scientific-attack-2026.json) ([open in Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/library-layers/boston-scientific-attack-2026.json)), listed on [the Navigator layers page](/navigator/index.md). It is pinned to ATT&CK v20 Enterprise; both techniques carry score 40 (a candidate the record allows but does not state), and each comment names the source number.

## Cross-cutting themes

- **The edge is the front door.** An intrusion through one external-facing management device preceded a global outage [13] [14] (**Confirmed**); that the device alone was enough is **Inferred**; the [Healthcare Threat Actor Watchlist](/case-studies/HEALTHCARE_THREAT_WATCHLIST.md) shows the same door across the sector [28] (**Inferred** as lineage).
- **Disruption without encryption.** CrowdStrike found no evidence of encryption at Boston Scientific [13], Stryker reported no indication of ransomware or malware in its first 8-K [26] (see [The Stryker Device-Wipe Attack of March 2026](/case-studies/STRYKER_HANDALA_WIPER_2026.md)), and both companies later found their incidents material [14] [27] (**Confirmed**); outage cost does not depend on an encryptor (**Inferred**).
- **Disclosure ran in stages.** An Item 8.01 filing, dated updates, an Item 1.05 filing, a forensic summary, then the 10-Q [1] [3] to [14] [18] (**Confirmed**).

## Sources

All sources were opened on 11 November 2026. Addresses shown as code rather than as links refuse automated link checkers (the sec.gov filings); copy them into a browser to open them.

| # | Source | URL | Opened | Grade |
|---|---|---|---|---|
| 1 | Boston Scientific, Form 8-K Item 8.01, filed 26 Aug 2026 | `https://www.sec.gov/Archives/edgar/data/885725/000088572526000056/bsx-20260826.htm` | 2026-11-11 | Confirmed |
| 2 | SEC EDGAR submissions record, CIK 0000885725 | [data.sec.gov/submissions/CIK0000885725.json](https://data.sec.gov/submissions/CIK0000885725.json) | 2026-11-11 | Confirmed |
| 3 | Boston Scientific, incident update, 26 Aug 2026 (archive) | [news.bostonscientific.com/8-26-26-cyber-update-archive](https://news.bostonscientific.com/8-26-26-cyber-update-archive) | 2026-11-11 | Confirmed |
| 4 | Boston Scientific, incident update, 27 Aug 2026 (archive) | [news.bostonscientific.com/8-27-26-cyber-archive](https://news.bostonscientific.com/8-27-26-cyber-archive) | 2026-11-11 | Confirmed |
| 5 | Boston Scientific, incident update, 28 Aug 2026 (archive) | [news.bostonscientific.com/8-28-26-cyber-update-archive](https://news.bostonscientific.com/8-28-26-cyber-update-archive) | 2026-11-11 | Confirmed |
| 6 | Boston Scientific, incident update, 29 Aug 2026 (archive) | [news.bostonscientific.com/8-29-26-cyber-update-archive](https://news.bostonscientific.com/8-29-26-cyber-update-archive) | 2026-11-11 | Confirmed |
| 7 | Boston Scientific, incident update, 30 Aug 2026 (archive) | [news.bostonscientific.com/8-30-26-cyber-archive](https://news.bostonscientific.com/8-30-26-cyber-archive) | 2026-11-11 | Confirmed |
| 8 | Boston Scientific, incident update and FAQ, 3 Sep 2026 (archive) | [news.bostonscientific.com/9-3-26-cyber-update-archive](https://news.bostonscientific.com/9-3-26-cyber-update-archive) | 2026-11-11 | Confirmed |
| 9 | Boston Scientific, incident update, 5 Sep 2026 (archive) | [news.bostonscientific.com/9-5-26-cyber-update-archive](https://news.bostonscientific.com/9-5-26-cyber-update-archive) | 2026-11-11 | Confirmed |
| 10 | Boston Scientific, incident update, 8 Sep 2026 (archive) | [news.bostonscientific.com/9-8-26-cyber-update-archive](https://news.bostonscientific.com/9-8-26-cyber-update-archive) | 2026-11-11 | Confirmed |
| 11 | Boston Scientific, incident update, 9 Sep 2026 (archive) | [news.bostonscientific.com/9-09-26-cyber-update-archive](https://news.bostonscientific.com/9-09-26-cyber-update-archive) | 2026-11-11 | Confirmed |
| 12 | Boston Scientific, update on recent cybersecurity incident, latest update 22 Sep 2026 | [news.bostonscientific.com/update-on-recent-cybersecurity-incident](https://news.bostonscientific.com/update-on-recent-cybersecurity-incident) | 2026-11-11 | Confirmed |
| 13 | CrowdStrike Investigation Summary, 22 Sep 2026, published by Boston Scientific | [news.bostonscientific.com/download/Crowdstrike+Investigation+Summary...](https://news.bostonscientific.com/download/Crowdstrike+Investigation+Summary+%289.22.2026%29.pdf) | 2026-11-11 | Confirmed |
| 14 | Boston Scientific, Form 8-K Item 1.05, report date 7 Sep 2026, filed 8 Sep 2026 | `https://www.sec.gov/Archives/edgar/data/885725/000088572526000059/bsx-20260907.htm` | 2026-11-11 | Confirmed |
| 15 | Boston Scientific, customer notice CRM-2582805-AA, Cardiac Device Remote Monitoring Activation Capability Restored, 8 Sep 2026 | [bostonscientific.com/.../crm-2582805-aa_latitude_activation_icm_and_crm.pdf](https://www.bostonscientific.com/content/dam/bostonscientific/crm/crm-2582805-aa_latitude_activation_icm_and_crm.pdf) | 2026-11-11 | Confirmed |
| 16 | Boston Scientific, Q2 2026 earnings release, 29 Jul 2026 | `https://www.sec.gov/Archives/edgar/data/885725/000088572526000051/q22026earningsrelease.htm` | 2026-11-11 | Confirmed |
| 17 | Boston Scientific, Q3 2026 earnings release (Ex. 99.1), 28 Oct 2026 | `https://www.sec.gov/Archives/edgar/data/885725/000088572526000066/earningsrelease_live.htm` | 2026-11-11 | Confirmed |
| 18 | Boston Scientific, Form 10-Q for the quarter ended 30 Sep 2026, filed 2 Nov 2026 | `https://www.sec.gov/Archives/edgar/data/885725/000088572526000070/bsx-20260930.htm` | 2026-11-11 | Confirmed |
| 19 | Boston Scientific, newsroom release list | [news.bostonscientific.com/news-releases](https://news.bostonscientific.com/news-releases) | 2026-11-11 | Confirmed |
| 20 | CISA, KEV catalog JSON feed, version 2026.11.10 | [cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) | 2026-11-11 | Inferred (absence) |
| 21 | Team Star Wolf Intelligence Hub, feed.json | [teamstarwolf.github.io/intelligence-hub/data/feed.json](https://teamstarwolf.github.io/intelligence-hub/data/feed.json) | 2026-11-11 | Confirmed |
| 22 | BleepingComputer, Boston Scientific says cyberattack disrupted operations globally, 26 Aug 2026 | [bleepingcomputer.com/news/security/...](https://www.bleepingcomputer.com/news/security/boston-scientific-says-cyberattack-disrupted-operations-globally/) | 2026-11-11 | Reported |
| 23 | MedTech Dive, Boston Scientific unlikely to meet guidance due to cyberattack, 8 Sep 2026 | [medtechdive.com/news/...](https://www.medtechdive.com/news/boston-scientific-unlikely-to-meet-guidance-due-to-cyberattack/829802/) | 2026-11-11 | Reported |
| 24 | MedTech Dive, Boston Scientific fully restores operations after cyberattack, 11 Sep 2026 | [medtechdive.com/news/...](https://www.medtechdive.com/news/boston-scientific-fully-restores-operations-after-cyberattack/830182/) | 2026-11-11 | Reported |
| 25 | MedTech Dive, Cyberattacks have plagued the medtech industry in 2026, updated 17 Sep 2026 | [medtechdive.com/news/...](https://www.medtechdive.com/news/cyberattacks-have-plagued-the-medtech-industry-in-2026/828489/) | 2026-11-11 | Reported |
| 26 | Stryker, Form 8-K Item 8.01, 11 Mar 2026 | `https://www.sec.gov/Archives/edgar/data/310764/000119312526102460/d76279d8k.htm` | 2026-11-11 | Confirmed |
| 27 | Stryker, Form 8-K/A Item 1.05, 9 Apr 2026 | `https://www.sec.gov/Archives/edgar/data/310764/000119312526149607/d112875d8ka.htm` | 2026-11-11 | Confirmed |
| 28 | TeamStarWolf library, Healthcare Threat Actor Watchlist | [/case-studies/HEALTHCARE_THREAT_WATCHLIST.md](/case-studies/HEALTHCARE_THREAT_WATCHLIST.md) | 2026-11-11 | Confirmed |
| 29 | TeamStarWolf library, Change Healthcare 2024 | [/case-studies/CHANGE_HEALTHCARE_2024.md](/case-studies/CHANGE_HEALTHCARE_2024.md) | 2026-11-11 | Confirmed |
| 30 | TeamStarWolf library data: `data/attack/technique_profiles.jsonl`, `technique_to_d3fend.jsonl`, `d3fend_countermeasures.jsonl`, `mitigation_to_technique.jsonl`, `data/weaknesses/capec.jsonl` and the `mitre/` tree | [github.com/TeamStarWolf/TeamStarWolf/tree/main/data](https://github.com/TeamStarWolf/TeamStarWolf/tree/main/data) | 2026-11-11 | Confirmed |

Not checked, so not cited: CISA, FBI, HHS or FDA statements beyond the KEV catalog, leak sites, the investor-conference remarks themselves (relayed by [24]), the Stifel and J.P. Morgan notes (relayed by [23]) and the Q3 earnings-call transcript.

*© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.*

*© The MITRE Corporation. Includes material from the Common Weakness Enumeration (CWE™), used under the CWE Terms of Use. https://cwe.mitre.org/*

*© The MITRE Corporation. Includes material from the Common Attack Pattern Enumeration and Classification (CAPEC™), used under the CAPEC Terms of Use. https://capec.mitre.org/*

*© The MITRE Corporation. Includes material from MITRE D3FEND™, used under the D3FEND Terms of Use. https://d3fend.mitre.org/*

*The terms for every MITRE dataset used here are recorded in [THIRD_PARTY_NOTICES.md](/THIRD_PARTY_NOTICES.md).*

## Related references

- [The Year 2026 in Intrusions](/case-studies/CHRONICLE_2026.md), [The Stryker Device-Wipe Attack of March 2026](/case-studies/STRYKER_HANDALA_WIPER_2026.md), [Healthcare Threat Actor Watchlist](/case-studies/HEALTHCARE_THREAT_WATCHLIST.md), [Change Healthcare 2024](/case-studies/CHANGE_HEALTHCARE_2024.md), [ICS Attacks and Advisories 2024 to 2026](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md)
- [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [Notable Incidents](/NOTABLE_INCIDENTS.md)
- [CVE Reference](/CVE_REFERENCE.md), [CWE Reference](/CWE_REFERENCE.md), [CAPEC Reference](/CAPEC_REFERENCE.md), [D3FEND Reference](/D3FEND_REFERENCE.md)
- [Edge Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md), [Network Defense Reference](/NETWORK_DEFENSE_REFERENCE.md), [Healthcare Security Reference](/HEALTHCARE_SECURITY_REFERENCE.md), [ICS and OT Security Reference](/ICS_OT_SECURITY_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md), [Ransomware Defense Reference](/RANSOMWARE_DEFENSE_REFERENCE.md)
- [Vulnerability Prioritization Reference](/VULNERABILITY_PRIORITIZATION_REFERENCE.md), [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md)
- Techniques: [T1190 Exploit Public-Facing Application](/mitre/techniques/T1190.md), [T1133 External Remote Services](/mitre/techniques/T1133.md), [T1486 Data Encrypted for Impact](/mitre/techniques/T1486.md) (no evidence of encryption)
- Mitigations: [M1035 Limit Access to Resource Over Network](/mitre/mitigations/M1035.md), [M1042 Disable or Remove Feature or Program](/mitre/mitigations/M1042.md), [M1030 Network Segmentation](/mitre/mitigations/M1030.md), [M1051 Update Software](/mitre/mitigations/M1051.md), [M1032 Multi-factor Authentication](/mitre/mitigations/M1032.md)
- CAPEC: [CAPEC-555](/mitre/capec/CAPEC-555.md)
- [Navigator layers](/navigator/index.md), including this study's layer, [boston-scientific-attack-2026.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/boston-scientific-attack-2026.json)
- The [Team Star Wolf Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/)
- [All case studies](/case-studies/README.md)
