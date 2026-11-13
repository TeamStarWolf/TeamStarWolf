# The FBI Surveillance System Breach of 2026: A Case Study

*A TeamStarWolf case study. Published 11 November 2026; every source checked as of that date.*

[All case studies](/case-studies/README.md) · Related: [Threat Actors: China](/case-studies/THREAT_ACTORS_CHINA.md), [The Year 2026 in Intrusions](/case-studies/CHRONICLE_2026.md), [SolarWinds SUNBURST](/case-studies/SOLARWINDS_SUNBURST.md), [Notable Incidents](/NOTABLE_INCIDENTS.md), [Telecom and 5G Security Reference](/TELECOM_5G_SECURITY_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Government and public-sector security leaders, third-party and supplier risk teams, detection engineers, incident responders and threat intelligence analysts

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 18 min (4,070 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want the dated record of the 2026 breach of an FBI system holding surveillance returns, how much of it rests on anonymous sources, or which third-party and logging controls the case argues for

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [Part 1: what happened](#part-1-what-happened), [Part 5: the defender and vulnerability-management view](#part-5-the-defender-and-vulnerability-management-view)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md), [Telecom and 5G Security Reference](/TELECOM_5G_SECURITY_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md), [Threat Actors: China](/case-studies/THREAT_ACTORS_CHINA.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive summary

The people most exposed by this breach are the subjects of FBI investigations and the people the FBI was monitoring (**Inferred** from [1] [11]). The affected system held returns from legal process, such as pen register and trap and trace surveillance returns, and personal information on people the FBI was investigating, according to the notices to Congress that outlets reviewed [1] [10] [11]; Bloomberg describes electronic surveillance data and PII [13] (**Reported**). Two people familiar with a later notice said the phone numbers of people under FBI monitoring were likely exposed [11] (**Reported**).

The FBI began investigating "abnormal log information" on an unclassified system on 17 February 2026 [1]; Reuters and Bloomberg give the same date [6] [13] (**Reported**). An early-March notice said the actor's techniques "appear sophisticated", including use of a commercial Internet Service Provider vendor's infrastructure to exploit FBI network security controls [13] (**Reported**). On 23 March senior Justice Department officials declared the intrusion a "major incident" under the Federal Information Security Modernization Act (FISMA) [13] (**Reported**). An FBI spokesperson later said "the access was obtained through a third party" [11] (**Reported**).

No official source names an actor. The China link rests on anonymous US officials quoted by the Wall Street Journal and Politico [6] [7] [9] (**Reported**), and whether Salt Typhoon is involved is, in CNN's and the WSJ's words, unclear [2] [7] (**Reported**). The Intelligence Hub feed has no row for the incident [19] (**Demonstrated**), and no CVE, KEV entry, vendor advisory or government cybersecurity advisory tied to it was found in any source opened (**Inferred**).

### Key facts at a glance

| Field | Value |
|---|---|
| Victim | The FBI: an unclassified system on its network holding "law enforcement sensitive information" [1] [9] (**Reported**) |
| Data on the system | Pen register and trap and trace returns, and PII on subjects of FBI investigations [1] [10] [11]; call and internet-activity records, not call or message content, per WSJ sources [7] (**Reported**) |
| Detection | 17 February 2026, from abnormal log information [1] [6] [13] (**Reported**) |
| Entry path | "Through a third party" (FBI spokesperson) [11]; a commercial ISP vendor's infrastructure (early-March notice) [13] (**Reported**) |
| Data reported exposed | Phone numbers of monitored targets; no count given [11] (**Reported**) |
| Attribution | None official [13]; "China-linked" per anonymous US officials [6] [9] (**Reported**) |
| FISMA status | Major incident, determined 23 March 2026 [13] (**Reported**) |
| CVE and KEV | None found [19] (**Demonstrated**) |
| Status | Forensics and remediation ongoing as of early April [13]; no hearing, IG report or formal attribution found since (**Inferred** from searches run 11 November 2026; no source row) |

### Key findings

- **Abnormal log information was the first reported signal.** The investigation began with abnormal log information on 17 February [1] [13] (**Reported**). Log telemetry on a sensitive system was the control that worked (**Inferred**).
- **Third-party trust was the exposed control** (**Inferred**). The reported path was a commercial ISP vendor's infrastructure [13] and "a third party" [11] (**Reported**). The FBI's own network security controls were what the actor exploited (**Reported** in the notice [13]).
- **The surveillance returns are metadata, and metadata is enough.** Pen register and trap and trace tools collect metadata, not content [11] [7] (**Reported**). Target phone numbers tell an adversary who the FBI is watching (**Inferred**, following the expert view in [11]).
- **Attribution is press-sourced.** Every China attribution comes from unnamed officials and aides [6] [9] [10]; the House Homeland Security chair placed the intrusion within PRC targeting on the record but cited no evidence, and Nextgov had not confirmed a definitive China link [11] (**Reported**).

### Top recommendations

1. Inventory every vendor and carrier path into systems that hold lawful-process data, and segment them from the rest of the network [11] [13] (**Inferred**).
2. Keep and review logs on those systems; the only detection on the record came from logs [1] (**Inferred**).
3. Treat surveillance metadata as highly sensitive data: encrypt it, restrict access and audit reads [10] [13] (**Inferred**).
4. Rehearse the FISMA major-incident path, including the seven-day notice to Congress [16] (**Inferred**).

## Scope and method

This brief covers the intrusion the FBI began investigating on 17 February 2026, the response through early April 2026, and what could be found up to 11 November 2026. The notices to Congress were not published. Every detail from them is known only through outlets that say they reviewed them, so those details are graded Reported, never Confirmed. No FBI, DOJ or CISA web page about this incident was found. Tradecraft is described at advisory level.

| Grade | Meaning in this study |
|---|---|
| Confirmed | A primary opened for this study: the FISMA statute or a CISA or FBI publication |
| Reported | Journalism, including official statements and notices as outlets quote them, and commentary |
| Demonstrated | A check this study ran itself: the Intelligence Hub feed search and the library page checks |
| Inferred | This study's own reasoning from cited facts, labelled where it appears |

## Part 1: what happened

| Date | Event | Sources | Grade |
|---|---|---|---|
| 13 Nov 2024 | Context: the FBI and CISA say PRC-affiliated actors compromised several telecom companies and copied information subject to US law enforcement requests made under court orders | [17] | Confirmed |
| 27 Aug 2025 | Context: AA25-239A, from 23 co-sealing agencies, names three China-based companies tied to the Salt Typhoon cluster; revised 3 Sep 2025 | [18] | Confirmed |
| 17 Feb 2026 | The FBI begins investigating abnormal log information on an unclassified system on its network | [1] [6] [13] | Reported |
| 4 Mar 2026 | The FBI first tells Congress it is investigating suspicious activity on an internal system holding "law enforcement sensitive information" | [9] | Reported |
| Early Mar 2026 | The DOJ and FBI notice says scope and impact are not yet known, and that the actor's techniques "appear sophisticated", including use of a commercial ISP vendor's infrastructure | [13] | Reported |
| 5 Mar 2026 | The FBI says it "identified and addressed suspicious activities on FBI networks" and used all its technical capabilities to respond; a CNN source ties the system to managing wiretaps and foreign intelligence surveillance warrants | [2] [3] | Reported |
| 5 Mar 2026 | Nextgov gets the same statement, cannot confirm the wiretap link and says it is unclear whether Salt Typhoon or another actor is involved | [4] | Reported |
| 6 Mar 2026 | The WSJ reports that US investigators believe Chinese-government-affiliated hackers are responsible; the FBI declines comment and the Chinese embassy does not respond | [6] [7] | Reported |
| 6 Mar 2026 | TechRadar repeats the FBI statement and notes that suspicion of Salt Typhoon is unconfirmed | [5] | Reported |
| 10 Mar 2026 | Malwarebytes calls the system the "Digital Collection System Network" (DCSNet), a name not found in any quoted notice wording | [8] | Reported |
| 23 Mar 2026 | Senior DOJ officials determine the intrusion is a FISMA "major incident" | [13] | Reported |
| Week of 30 Mar 2026 (Politico, one aide) or week of 23 Mar (Fox News) | Congress is told of the major-incident determination | [9] [10] | Reported |
| 1 Apr 2026 | Politico publishes the major-incident designation | [9] | Reported |
| 2 Apr 2026 | Fox News reports, from a single outlet, that the hack involved FBI systems in the Virgin Islands rather than headquarters | [10] | Reported |
| 3 Apr 2026 | An FBI spokesperson says "the access was obtained through a third party"; people familiar with the notice say target phone numbers were likely exposed, and that the agency had identified exposed phone numbers | [11] | Reported |
| 3 Apr 2026 | TechRepublic reports a DOJ working group and quotes a US official calling the breach "embarrassing" | [12] | Reported |
| 6 Apr 2026 | The later notice, per Bloomberg: forensic examination and remediation ongoing, a working group created, no actor named; Bloomberg adds that the breach had prompted a criminal probe | [13] | Reported |
| 11 Nov 2026 | No hearing, IG report, formal attribution or joint advisory about this incident is found; the Hub feed has no row for it | searches run 11 Nov 2026; [19] | Inferred; Demonstrated |

From the reported dates, about 15 days passed between opening the investigation and the first notice to Congress, and 34 days before the major-incident determination [9] [13] (**Inferred**). The record does not say when data theft was confirmed or whether the intrusion is contained (**Inferred**).

## Part 2: the intrusion record

**The system.** The notices, as AP, Nextgov and Politico (quoted by Fox News) report them, describe an unclassified system holding law enforcement sensitive information: returns from legal process, such as pen register and trap and trace surveillance returns, and PII on subjects of FBI investigations [1] [10] [11]; Bloomberg's reading is electronic surveillance data and PII on subjects of investigations [13] (**Reported**). WSJ sources add that it holds records of incoming and outgoing calls, IP and website addresses and some routing information on people under surveillance, but not the content of calls or messages [7] (**Reported**).

A CNN source described it more broadly, as the system the FBI uses to manage wiretaps and foreign intelligence surveillance warrants [2] (**Reported**). Bloomberg's own summary uses the same framing [13] (**Reported**). That goes beyond the notice wording, which covers pen register and trap and trace returns [1] (**Reported**). The name "Digital Collection System Network" comes from Malwarebytes and from a commentator quoted by Security Magazine [8] [14], not from any notice wording an outlet quotes (**Reported**). This brief uses the notice wording.

**The entry path.** Two statements describe it. The early-March notice says the actor's techniques included using a commercial Internet Service Provider vendor's infrastructure to exploit FBI network security controls [13] (**Reported**). On 3 April an FBI spokesperson said "the access was obtained through a third party" [11] (**Reported**). Neither names the vendor, the controls or how they were defeated. No product, version, exploit or malware is named anywhere in the record [13] [19] (**Inferred**).

**Detection and response.** The investigation began from abnormal log information [1] (**Reported**). The FBI said it found "anomalous activity" on an unclassified network and moved to remediate it [11] (**Reported**). In early April, FBI and DOJ forensic examination and remediation were still ongoing [13] (**Reported**). No source describes eviction, rebuilt systems or a confirmed end date (**Inferred**).

## Part 3: who and why

Attribution here is anonymous-source reporting, nothing more.

- **The government.** Neither the FBI statement nor the DOJ and FBI notices named who was responsible, and the later notice did not give the extent of the breach or say which data was compromised [13] (**Reported**). No official FBI or DOJ attribution or group name appears in any source opened [11] (**Reported**).
- **The WSJ.** US investigators believe hackers affiliated with the Chinese government were responsible; the investigation is early and conclusions could change [6] [7] (**Reported**).
- **Politico.** A "China-linked" intrusion, per one congressional aide and two US officials [9] (**Reported**). Fox News says it was told China was responsible [10] (**Reported**, single outlet).
- **Nextgov.** It had not independently confirmed a definitive link to China [11] (**Reported**).
- **Salt Typhoon.** CNN and the WSJ both say it is unclear whether Salt Typhoon or another actor is behind the breach [2] [7] (**Reported**). A commentator in Security Magazine compared the vendor-ISP path to Salt Typhoon's 2024 lawful-intercept compromises [14]; that is commentary, not the record (**Reported**). On the record, House Homeland Security chair Rep. Andrew Garbarino set the intrusion within PRC targeting of government systems "through trusted third-party infrastructure as seen in the Salt Typhoon campaign" [11]; that is a comparison, not attribution (**Reported**).

The background is documented but separate. In November 2024 the FBI and CISA said PRC-affiliated actors had copied information subject to court-ordered US law enforcement requests from telecom companies [17] (**Confirmed**). AA25-239A ties three China-based companies to the Salt Typhoon cluster but does not discuss lawful intercept systems [18] (**Confirmed**). ATT&CK tracks Salt Typhoon as [G1045](/mitre/groups/G1045.md), and [Threat Actors: China](/case-studies/THREAT_ACTORS_CHINA.md) covers the 2024 telecom statement [20] (**Demonstrated**). Both are linked here as context, not as attribution for this incident. A 29 August 2026 DOJ correction concerns a separate China-attributed campaign and does not mention this incident [15] (**Reported**).

No source states a motive. The data's likely value is counterintelligence (**Inferred**): John Fokker of Trellix told Nextgov that target phone numbers could help an adversary map relationships, decide which contacts to drop or check whether an asset is compromised [11] (**Reported**).

Two other FBI incidents are distinct. Politico says this breach does not appear connected to the Iran-linked compromise of the FBI Director's personal email in late March [9], and TechRepublic also treats them as separate [12] (**Reported**). CNN recalls a 2023 breach of a New York FBI field office system used in child exploitation investigations, noting that FBI breaches are rarely disclosed [2] (**Reported**).

## Part 4: impact and response

**The people.** Subjects of FBI investigations, whose PII was on the system [1] [13], and people under monitoring, whose phone numbers were reported exposed [11] (**Reported**). No count is given [11].

**The FBI and DOJ.** The FBI said it identified and addressed the activity [3] [4] and is following FISMA steps, including notifying Congress [11] (**Reported**). The DOJ created a working group on cyber resilience and incident response and, per Bloomberg, the breach prompted a criminal probe [13] (**Reported**). A CNN source said senior FBI and DOJ officials focused on civil liberties and national security were responding. Current and former officials told CNN that the FBI's cyber response capacity had diminished, with senior IT and Salt Typhoon response officials pushed out under the current Director [2] (**Reported**).

**The wider government.** On 6 March Politico, as cited by Reuters, reported the White House, NSA, CISA and FBI working together on the investigation; a White House official said it "regularly convenes meetings" on cyber threats, CISA referred questions to the FBI and the NSA did not respond [6] (**Reported**).

**Congress.** FISMA requires notice to the named committees "not later than 7 days after" there is a reasonable basis to conclude a major incident has occurred [16] (**Confirmed**). One congressional aide told Politico that Congress was told of the determination in the week of 30 March [9]; Fox News, on 2 April, said it was told the designation was made 'last week' when members were notified [10] (**Reported**). The two accounts differ and neither gives a day, so whether the seven-day clock was met cannot be judged from public sources (**Inferred**). House Homeland Security chair Rep. Andrew Garbarino said the committee was in contact with CISA, assessing scope, and noted the intrusion took place during the DHS shutdown; ranking member Rep. Bennie Thompson called the reports "disturbing" and blamed cyber workforce cuts [11] (**Reported**).

**CVE and KEV.** The Intelligence Hub feed (content date 11 November 2026, 6,049 rows) and its February to April 2026 shards have no row for this incident, and no source opened ties a CVE or KEV entry to it [19] (**Demonstrated**).

## Part 5: the defender and vulnerability-management view

- **A CVE queue would have shown nothing on the public record.** The reported path is a vendor's infrastructure and a third party, and no listed flaw appears anywhere in the record [11] [13] [19] (**Inferred**). Track third-party connectivity as an exposure in its own right.
- **Write the notice timeline into the playbook.** The 15-day and 34-day intervals [9] [13] show how long scoping takes (**Inferred**); FISMA's seven-day notice runs from the point there is a reasonable basis to conclude a major incident occurred [16] (**Confirmed**), which can come before a formal determination (**Inferred**).

### What is overstated and what is understated

- *Overstated:* calling it a hack of the FBI's "wiretap system" or "DCSNet". The wiretap framing comes from a CNN source [2] and from Bloomberg's and TechRadar's own wording [13] [5], and the DCSNet name from secondary writers [8] [14]; the notice wording as quoted covers pen register and trap and trace returns and PII [1] [10] [11] (**Reported**). China attribution stated as fact, and any Salt Typhoon link, go beyond the record: no government source names an actor [13] (**Reported**).
- *Understated:* the third-party path, which the FBI itself confirmed in its spokesperson's words [11] (**Reported**); the counterintelligence value of target phone numbers [11] (**Reported**); and the major-incident determination itself, which Politico reads as suggesting that sensitive data stored directly on FBI systems was compromised [9] (**Reported**).

## MITRE mappings

This Part binds the record to ATT&CK v20.0 Enterprise and D3FEND, with names and tactics from the library's `data/attack/` files [20]. No source describes industrial systems, so no ATT&CK for ICS techniques apply.

### Groups, software and campaigns

| Object | ATT&CK id | Relationship to this record |
|---|---|---|
| Salt Typhoon | [G1045](/mitre/groups/G1045.md) | Context only: named as an open question by CNN and the WSJ [2] [7]; not attributed by any source |

No software or campaign is bound: no malware or tool is named in the record [13].

### ATT&CK Enterprise techniques

| ID | Name | Tactic(s) | Dated event or report | Sources |
|---|---|---|---|---|
| [`T1199`](/mitre/techniques/T1199.md) | Trusted Relationship | Initial Access | Early-March 2026 notice: use of a commercial ISP vendor's infrastructure to exploit FBI network security controls; 3 Apr 2026 FBI statement: access "obtained through a third party" | [11] [13] |
| [`T1213`](/mitre/techniques/T1213.md) | Data from Information Repositories | Collection | Phone numbers of monitored targets identified as exposed from a system holding surveillance returns and PII, reported 3 Apr 2026 | [11] [13] |

Fit notes (**Inferred**): T1199 fits the FBI's own words directly. T1213 is a partial fit: the record says data was exposed, not how it was taken. No exfiltration technique is bound, because theft is not described. T1195 Supply Chain Compromise is left out: no product or update channel is named, and "supply chain" is a secondary writer's framing [8]. T1584 Compromise Infrastructure is left out: the notice does not say whether the vendor's infrastructure was compromised or only used. No sub-technique of T1213 fits a system the record does not describe.

### CWE and CAPEC

No CVE applies, so no CWE is bound [19]. The library relates CAPEC-150 to T1213 [20], but the record describes nothing specific to that pattern, so no CAPEC entry is bound.

### D3FEND countermeasures

| D3FEND countermeasure | Techniques the library maps it to (from this study) | Where it meets the record |
|---|---|---|
| [Network Traffic Filtering](/mitre/d3fend/network-traffic-filtering.md) (D3-NTF) | T1199 | Restricting what a vendor's infrastructure can reach [13] (**Inferred**) |
| [Network Traffic Community Deviation](/mitre/d3fend/network-traffic-community-deviation.md) (D3-NTCD) | T1199 | Flagging vendor-path traffic that departs from its baseline [13] (**Inferred**) |
| [Protocol Metadata Anomaly Detection](/mitre/d3fend/protocol-metadata-anomaly-detection.md) (D3-PMAD) | T1199 | The anomaly-led detection the record describes [1] [11] (**Inferred**) |
| [Session Termination](/mitre/d3fend/session-termination.md) (D3-ST) | T1199 | Remediation of the third-party access [11] [13] (**Inferred**) |

The library maps no D3FEND countermeasure to T1213. Related mitigations: [M1030 Network Segmentation](/mitre/mitigations/M1030.md) and [M1018 User Account Management](/mitre/mitigations/M1018.md) for T1199, and [M1047 Audit](/mitre/mitigations/M1047.md) and [M1041 Encrypt Sensitive Information](/mitre/mitigations/M1041.md) for T1213. See the [D3FEND Reference](/D3FEND_REFERENCE.md).

### Navigator layer

The study's Navigator layer is [`navigator/library-layers/fbi-surveillance-system-breach-2026.json`](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/fbi-surveillance-system-breach-2026.json) ([open in Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/library-layers/fbi-surveillance-system-breach-2026.json)), listed on [the Navigator layers page](/navigator/index.md). It is pinned to ATT&CK v20 Enterprise. Because every primary here is unpublished, scores measure fit within Reported sources: 60 means official words, as quoted, state the behavior and the technique fits directly; 30 means the fit is partly the study's inference. Each comment names its source numbers.

## Cross-cutting themes

- **Trusted third parties carry the risk.** As in [SolarWinds SUNBURST](/case-studies/SOLARWINDS_SUNBURST.md), a party the victim trusted was the way in, though here no software update is involved [11] [13] (**Inferred**).
- **Lawful-access data is a target class.** The 2024 telecom compromises reached data from court-ordered requests [17] (**Confirmed**); this incident reportedly reached the government's own surveillance returns [1] [13] (**Reported**). Data built for lawful access needs the controls of a crown-jewel system (**Inferred**).
- **Undisclosed primaries shape the story.** With the notices unpublished, framings such as "wiretap system" and "DCSNet" spread faster than the notice wording [2] [8] (**Inferred**).
- **Attribution by leak is not attribution.** Anonymous officials named China within three weeks of detection; eight months later no government source has [6] [13] and searches run 11 November 2026 (**Inferred**).

## Sources

All sources were opened on 11 November 2026.

| # | Source | URL | Opened | Grade |
|---|---|---|---|---|
| 1 | AP (Eric Tucker, Alanna Durkin Richer), FBI investigating suspicious cyber activity on system holding sensitive surveillance information, 5 Mar 2026, syndicated by ClickOnDetroit | [clickondetroit.com/news/politics/2026/03/05/...](https://www.clickondetroit.com/news/politics/2026/03/05/fbi-investigating-suspicious-cyber-activity-on-system-holding-sensitive-surveillance-information/) | 2026-11-11 | Reported |
| 2 | CNN (Paula Reid), FBI investigating cyber breach of critical surveillance network, 5 Mar 2026 | [cnn.com/2026/03/05/politics/...](https://www.cnn.com/2026/03/05/politics/fbi-investigating-cyber-breach-critical-surveillance-network) | 2026-11-11 | Reported |
| 3 | CNN via KRDO, FBI investigating suspicious cyber activities on critical surveillance network, 5 Mar 2026 | [krdo.com/news/2026/03/05/...](https://krdo.com/news/2026/03/05/fbi-investigating-suspicious-cyber-activities-on-critical-surveillance-network/) | 2026-11-11 | Reported |
| 4 | Nextgov/FCW, FBI probing suspicious breach of bureau networks, 5 Mar 2026 | [nextgov.com/cybersecurity/2026/03/...](https://www.nextgov.com/cybersecurity/2026/03/fbi-probing-suspicious-breach-bureau-networks/411929/) | 2026-11-11 | Reported |
| 5 | TechRadar, FBI says it is investigating claims its systems were compromised, 6 Mar 2026 | [techradar.com/pro/security/...](https://www.techradar.com/pro/security/fbi-says-its-investigating-claims-its-systems-were-compromised-wire-taps-and-search-warrants-apparently-hijacked) | 2026-11-11 | Reported |
| 6 | Reuters (Chris Thomas, AJ Vicens, Jana Winter), US suspects China in breach of FBI surveillance network, WSJ reports, 6 Mar 2026, via GV Wire | [gvwire.com/2026/03/06/...](https://gvwire.com/2026/03/06/us-suspects-china-in-breach-of-fbi-surveillance-network-wsj-reports/) | 2026-11-11 | Reported |
| 7 | Wall Street Journal (Dustin Volz), China suspected in breach of FBI surveillance network, 6 Mar 2026, republished by To Vima | [tovima.com/wsj/...](https://www.tovima.com/wsj/china-suspected-in-breach-of-fbi-surveillance-network/amp/) | 2026-11-11 | Reported |
| 8 | Malwarebytes (Danny Bradbury), Hackers may have breached FBI wiretap network via supply chain, 10 Mar 2026 | [malwarebytes.com/blog/data-breaches/2026/03/...](https://www.malwarebytes.com/blog/data-breaches/2026/03/hackers-may-have-breached-fbi-wiretap-network-via-supply-chain) | 2026-11-11 | Reported |
| 9 | Politico (John Sakellariadis), FBI hack of surveillance system deemed major incident, 1 Apr 2026 (free portion) | [politico.com/news/2026/04/01/...](https://www.politico.com/news/2026/04/01/fbi-hack-surveillance-system-major-incident-00854237) | 2026-11-11 | Reported |
| 10 | Fox News, FBI notified Congress last week of China-linked hack deemed major incident, 2 Apr 2026 | [foxnews.com/politics/...](https://www.foxnews.com/politics/fbi-notified-congress-last-week-china-linked-hack-deemed-major-incident) | 2026-11-11 | Reported |
| 11 | Nextgov/FCW (David DiMolfetta), Suspected Chinese breach of FBI system exposed surveillance targets' phone numbers, 3 Apr 2026 | [nextgov.com/cybersecurity/2026/04/...](https://www.nextgov.com/cybersecurity/2026/04/suspected-chinese-breach-fbi-system-exposed-surveillance-targets-phone-numbers/412612/) | 2026-11-11 | Reported |
| 12 | TechRepublic (Aminu Abdullahi), China-linked FBI surveillance breach deemed major incident, 3 Apr 2026 | [techrepublic.com/article/...](https://www.techrepublic.com/article/news-china-linked-fbi-surveillance-breach-major-incident/) | 2026-11-11 | Reported |
| 13 | Bloomberg (Jake Bleiberg), FBI Calls Breach of Sensitive Agency Networks a 'Major Incident', 6 Apr 2026, via Insurance Journal (also opened at the amp.insurancejournal.com copy) | [insurancejournal.com/news/national/2026/04/06/864534.htm](https://www.insurancejournal.com/news/national/2026/04/06/864534.htm) | 2026-11-11 | Reported |
| 14 | Security Magazine, Breach of FBI surveillance system considered a major incident: security experts weigh in, 6 Apr 2026 | [securitymagazine.com/articles/102207-...](https://www.securitymagazine.com/articles/102207-breach-of-fbi-surveillance-system-considered-a-major-incident-security-experts-weigh-in) | 2026-11-11 | Reported |
| 15 | Al Jazeera (with Reuters), US revises statements suggesting Chinese hackers attacked agencies, 29 Aug 2026 (separate campaign, context) | [aljazeera.com/news/2026/8/29/...](https://www.aljazeera.com/news/2026/8/29/us-revises-statements-suggesting-chinese-hackers-attacked-agencies) | 2026-11-11 | Reported |
| 16 | 44 U.S.C. 3554 (FISMA), section (b)(7)(C)(iii)(III)(aa), Cornell Legal Information Institute | [law.cornell.edu/uscode/text/44/3554](https://www.law.cornell.edu/uscode/text/44/3554) | 2026-11-11 | Confirmed |
| 17 | FBI and CISA, Joint statement on People's Republic of China targeting of commercial telecommunications infrastructure, 13 Nov 2024 | [cisa.gov/news-events/news/joint-statement-fbi-and-cisa-...](https://www.cisa.gov/news-events/news/joint-statement-fbi-and-cisa-peoples-republic-china-prc-targeting-commercial-telecommunications) | 2026-11-11 | Confirmed |
| 18 | CISA and partners, AA25-239A, 27 Aug 2025, revised 3 Sep 2025 | [cisa.gov/news-events/cybersecurity-advisories/aa25-239a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-239a) | 2026-11-11 | Confirmed |
| 19 | Team Star Wolf Intelligence Hub, feed.json and the 2026-02 to 2026-04 v7 live and article shards (no row for this incident) | [teamstarwolf.github.io/intelligence-hub/data/feed.json](https://teamstarwolf.github.io/intelligence-hub/data/feed.json) | 2026-11-11 | Demonstrated |
| 20 | TeamStarWolf library data and pages: `data/attack/technique_profiles.jsonl`, `groups.jsonl`, `technique_to_d3fend.jsonl`, `d3fend_countermeasures.jsonl`, `data/weaknesses/capec.jsonl`, the `mitre/` tree including the G1045 page, and Threat Actors: China | [github.com/TeamStarWolf/TeamStarWolf/tree/main/data](https://github.com/TeamStarWolf/TeamStarWolf/tree/main/data) | 2026-11-11 | Demonstrated |

Not opened, so not cited as sources: the DOJ and FBI notices to Congress (not published), the Bloomberg original and Politico's 6 March story (both HTTP 403), the Politico body past its free portion, the WSJ original (paywalled) and Politico Pro. Searches run 2026-11-11 for hearings, IG reports, attribution and joint advisories found none; claims resting on them are graded Inferred and carry no source number.

*© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.*

*© The MITRE Corporation. Includes material from the Common Weakness Enumeration (CWE™), used under the CWE Terms of Use. https://cwe.mitre.org/*

*© The MITRE Corporation. Includes material from the Common Attack Pattern Enumeration and Classification (CAPEC™), used under the CAPEC Terms of Use. https://capec.mitre.org/*

*© The MITRE Corporation. Includes material from MITRE D3FEND™, used under the D3FEND Terms of Use. https://d3fend.mitre.org/*

*The terms for every MITRE dataset used here are recorded in [THIRD_PARTY_NOTICES.md](/THIRD_PARTY_NOTICES.md).*

## Related references

- [Threat Actors: China](/case-studies/THREAT_ACTORS_CHINA.md), [The Year 2026 in Intrusions](/case-studies/CHRONICLE_2026.md), [SolarWinds SUNBURST](/case-studies/SOLARWINDS_SUNBURST.md)
- [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [Notable Incidents](/NOTABLE_INCIDENTS.md)
- [CVE Reference](/CVE_REFERENCE.md), [D3FEND Reference](/D3FEND_REFERENCE.md)
- [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md), [Telecom and 5G Security Reference](/TELECOM_5G_SECURITY_REFERENCE.md), [Data Security Reference](/DATA_SECURITY_REFERENCE.md), [Zero Trust Reference](/ZERO_TRUST_REFERENCE.md), [Network Monitoring Reference](/NETWORK_MONITORING_REFERENCE.md), [SIEM Reference](/SIEM_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md), [Threat Intelligence Reference](/THREAT_INTELLIGENCE_REFERENCE.md)
- Group (context only): [G1045 Salt Typhoon](/mitre/groups/G1045.md)
- Techniques: [T1199 Trusted Relationship](/mitre/techniques/T1199.md), [T1213 Data from Information Repositories](/mitre/techniques/T1213.md)
- Mitigations: [M1030 Network Segmentation](/mitre/mitigations/M1030.md), [M1018 User Account Management](/mitre/mitigations/M1018.md), [M1047 Audit](/mitre/mitigations/M1047.md), [M1041 Encrypt Sensitive Information](/mitre/mitigations/M1041.md)
- [Navigator layers](/navigator/index.md), including this study's layer, [fbi-surveillance-system-breach-2026.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/fbi-surveillance-system-breach-2026.json)
- The [Team Star Wolf Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/)
- [All case studies](/case-studies/README.md)
