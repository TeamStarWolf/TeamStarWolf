# The IDScan.net Driver's License Breach of 2026: A Case Study

*A TeamStarWolf case study. Published 11 November 2026; every source checked as of that date.*

[All case studies](/case-studies/README.md) · Related: [The Year 2026 in Intrusions](/case-studies/CHRONICLE_2026.md), [Change Healthcare 2024](/case-studies/CHANGE_HEALTHCARE_2024.md), [The Cl0p File-Transfer Breaches](/case-studies/CL0P_FILE_TRANSFER_2023.md), [Threat Actors: China](/case-studies/THREAT_ACTORS_CHINA.md), [Notable Incidents](/NOTABLE_INCIDENTS.md), [Data Security Reference](/DATA_SECURITY_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Third-party risk and privacy teams, identity and access teams, detection engineers, fraud and help-desk leads and vulnerability management leads

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 15 min (3,511 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want the dated record of the 2026 IDScan.net breach and the Nexus driver's license service, why the vendor's notice and the reporting disagree, or which vendor, retention and monitoring controls the case argues for

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [Part 1: what happened](#part-1-what-happened), [Part 5: the defender and vulnerability-management view](#part-5-the-defender-and-vulnerability-management-view)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Data Security Reference](/DATA_SECURITY_REFERENCE.md), [Privacy Engineering Reference](/PRIVACY_ENGINEERING_REFERENCE.md), [Identity Security Reference](/IDENTITY_SECURITY_REFERENCE.md), [The Year 2026 in Intrusions](/case-studies/CHRONICLE_2026.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive summary

The people in this breach are anyone who handed a driver's license to a scanner at a rental counter, a dispensary or another business. The seller offered a reporter's own Virginia license as a free sample in a search service called Nexus. The reporter then found licenses belonging to nine friends and family members who agreed to a search, his mother among the people he names, plus two security researchers, an FBI assistant director and the US Defense Secretary [4] (**Demonstrated** by the reporter's own queries; **Reported** here). Some records, the reporter's own among them, carried front, back, infrared and ultraviolet scans, and some carried a customer photo [4] (**Demonstrated**).

The vendor, IDScan.net, an identity verification company, says an unauthorized third party accessed a portion of its cloud environment, limited to the VeriScan platform, between 4 April and 2 September 2026 [1] (**Confirmed**). It learned of possible unauthorized access on or around 1 September [1] (**Confirmed**), the day after a source pointed a journalist to the Nexus listing on a Russian-language criminal forum [4] (**Reported**).

No source states how the attacker got in. No CVE, KEV entry or government advisory applies in the data checked [15] (**Confirmed** for the Intelligence Hub data; a wider NVD and CISA search was not checked).

### Key facts at a glance

| Field | Value |
|---|---|
| Vendor | IDScan.net; Metairie, LA mailing address in its notice [1] (**Confirmed**); markets 21M+ verifications a month at 20,000+ locations [4] (**Reported**, company marketing) |
| System affected | "A portion of" the cloud environment, limited to the VeriScan platform; no other product identified (update of 29 Sep 2026) [1] [2] (**Confirmed**) |
| Access window | 4 Apr to 2 Sep 2026 per the vendor [1] (**Confirmed**); June 2025 to 1 Sep 2026 per Barracuda from record timestamps (scan dates) [13] (**Reported**); "over a year" per the seller [4] (**Reported**) |
| How the vendor learned | Information received on or around 1 Sep 2026 [1] (**Confirmed**); a journalist's source flagged the forum listing on 31 Aug [4] (**Reported**) |
| Entry vector | Not stated by the vendor or any report opened [1] [4] [5] [10] (**Inferred** from the absence) |
| Data per the vendor | Full name, contact information, date of birth, driver's license, passport and other government ID numbers, varying by customer configuration; no images listed; no count [1] (**Confirmed**) |
| Data per the reporting | Front, back, basic, IR and UV scans, some with a customer photo, timestamps in filenames that appear to be GMT [4] (**Demonstrated**) |
| Seller's figures | 153M+ US and Canadian licenses, 10M+ ID cards, 3M+ travel or international IDs, 579,000+ medical cards [4] (**Reported**, seller's claim) |
| Sold through | Nexus, offered by a new user on the Russian-language Exploit forum; offline the evening of 1 Sep 2026 [4] (**Reported**) |
| Attribution | Stops at the Nexus seller; no group named [4] [9] (**Inferred** from the absence) |
| CVE and KEV | None in the Intelligence Hub feed, KEV or 2026 history shards [15] (**Confirmed**) |
| Law enforcement and courts | FBI New Orleans field office opened an investigation on 1 Sep [4]; nine putative class actions reported in the Eastern District of Louisiana [12] (**Reported**) |

### Key findings

- **The vendor's notice describes numbers; the market showed pictures.** IDScan.net lists identifier fields and no images [1] (**Confirmed**). Krebs saw scans and photos in Nexus [4] (**Demonstrated**). An image is an impersonation kit; a number is not (**Inferred**).
- **Detection came from outside.** A journalist's source flagged the listing [4] (**Reported**); no source describes the vendor detecting the access itself (**Inferred** from the absence in [1]).
- **The access window may be wider than stated.** The vendor says 4 April [1] (**Confirmed**); the seller claimed over a year of continuous exfiltration [4] (**Reported**). Scan timestamps reach back to June 2025 [4] [13], which shows how long the platform retained images, not when they were taken (**Inferred**).

### Top recommendations

1. Inventory every place license images are captured and retained, including vendor platforms, and minimize central retention [7] (**Reported** advice; **Inferred** as a fit to this case).
2. Write logging, segregation, retention limits and breach notice into ID-scanning contracts, and assess resellers and downstream processors [7] (**Reported** advice).
3. Monitor bulk API, service and administrator access to stores of identity images [7] (**Reported** advice).
4. Stop treating a license image alone as proof of identity at help desks, and replace physical access credentials tied to exposed IDs [13] (**Reported** advice).

## Scope and method

This brief covers the VeriScan intrusion, the Nexus resale service, attribution and the response through 11 November 2026, at advisory level. The forum and Nexus were not visited; what they showed comes from the journalists who saw them.

| Grade | Meaning in this study |
|---|---|
| Confirmed | Stated in a primary opened for this study: the vendor's notice and website, a regulator list, Intelligence Hub data, or library data. The vendor's account of its own incident is Confirmed as the vendor's statement |
| Reported | Journalism, third-party analysis, the seller's claims, or a secondary account of an unopened primary |
| Demonstrated | A journalist's own test against the data, as published (Krebs's queries of the Nexus service) |
| Inferred | This study's own reasoning from cited facts, labelled where it appears |

## Part 1: what happened

| Date | Event | Sources | Grade |
|---|---|---|---|
| Feb 2025 | Caesars Entertainment says it stopped using IDScan in February 2025 and had no active accounts at the time of the incident | [4] | Reported |
| Jun 2025 | Earliest scan timestamps seen: Krebs's own record, and Barracuda's reading of the data (scan dates, not theft dates) | [4] [13] | Demonstrated [4], Reported [13] |
| 4 Apr 2026 | Start of the vendor-stated window of unauthorized access to a portion of its cloud environment | [1] [2] | Confirmed |
| 31 Aug 2026 | A source alerts Krebs to a Nexus listing on the Exploit forum, posted by a new user, offering Krebs's own Virginia license as a free sample | [4] | Reported |
| 1 Sep 2026 | Krebs observes nearly 400,000 records added in 24 hours and about 1.1 million Canadian results (473,673 from Ontario) | [4] | Demonstrated |
| 1 Sep 2026 | FBI New Orleans field office is probing an apparent breach involving idscan.net | [4] [8] | Reported |
| On or around 1 Sep 2026 | IDScan.net receives information that certain data may have been accessed without authorization | [1] | Confirmed |
| 1 Sep 2026, evening | Nexus goes offline (Krebs update at 8:56 pm ET); its login page says the service is no longer available | [4] | Reported |
| 2 Sep 2026 | End of the vendor-stated access window | [1] [2] | Confirmed |
| 2 Sep 2026 | A DoD spokesperson tells TechCrunch the department is evaluating the reports | [5] | Reported |
| 2 to 4 Sep 2026 | Nine putative class actions docketed against IDscan.net, Inc. in the Eastern District of Louisiana | [12] | Reported (dockets not opened) |
| 3 Sep 2026 | Techlicious removes Target from its list of IDScan.net users; NCC Group publishes control advice | [6] [7] | Reported |
| 4 Sep 2026 | Vendor notice first posted, per the notice itself | [1] | Confirmed |
| 10 Sep 2026 | Risky Business: class actions being prepared; Nexus operators did not claim to have deleted the data | [10] | Reported |
| 16 Sep 2026 | Krebs argues that federal limits on how ID scanners use, share or keep data might have avoided the breach | [11] | Reported |
| 29 Sep 2026 | Vendor notice updated: event limited to the VeriScan platform | [1] [2] | Confirmed |
| 11 Nov 2026 | No IDScan filing on the California AG breach list | [14] | Confirmed |

One notice, three dates: 4 September on the notice [1] (**Confirmed**), 8 September in Krebs's update [4] (**Reported**), 11 September on the homepage news list [3] (**Confirmed**). This study uses the notice's own date (**Inferred**).

## Part 2: the intrusion record

The vendor's account is short: "a portion of" its cloud environment, 4 April to 2 September 2026, and from the 29 September update no product other than VeriScan [1] [2] (**Confirmed**). It names no vulnerability, credential, misconfiguration or entry path, and no report does [1] [4] [5] [10] (**Inferred** from the absence). No patch or fixed version exists in the record. Containment is the vendor securing its cloud environment, plus the Nexus storefront going dark on 1 September [1] [4] (**Inferred**).

The data in the market was richer than the notice. The vendor lists full name, contact information, date of birth, and driver's license, passport and other government ID numbers, varying by how each customer configured VeriScan [1] (**Confirmed**). Krebs's own record, and some others, carried six image files (pairs of front and back images: a basic scan plus infrared and ultraviolet versions), some with a customer photo, with timestamps in the filenames that appear to be GMT; he found no passports [4] (**Demonstrated**). TechCrunch reports a forum post claiming about half a million new documents a day and an advert promising customer photos "if available" and passports [5] (**Reported**, seller's claims). That passport claim is overstated against what Krebs saw [4], though the vendor lists passport numbers as a possible field [1] (**Inferred**).

Collection looked ongoing: Krebs saw nearly 400,000 records added in 24 hours [4] (**Demonstrated**), and the seller claimed continuous exfiltration [4] (**Reported**). How the data left is not stated anywhere (**Inferred** from the absence).

## Part 3: who and why

Attribution stops at a seller.

- **The seller.** Nexus was offered by a new user on the Russian-language Exploit forum; the proprietor is not named [4] (**Reported**).
- **The victim link.** Krebs tied Nexus to idscan.net circumstantially: the nine people found confirmed travel on or near their record timestamps, and several had rented from Hertz that day; idscan.net documents IR and UV scanning; and a researcher's timestamp fell on a day when the only certain ID scan was at a dispensary chain that announced an idscan.net agreement in 2022 [4] (**Reported**). The vendor's notice confirms an intrusion but never names Nexus [1] (**Confirmed**). That the two are the same event is very likely: the vendor's window closes on 2 September, the day after Nexus was exposed and went offline [1] [4] (**Inferred**).
- **No group.** No source names a group or sponsor [1] [4] [5] [9] [10] (**Inferred** from the absence).
- **Motive.** No source states one. The seller ran a service selling search access [4] (**Reported**), so the evident motive is money (**Inferred**). Risky Business frames the data as feed for adversary intelligence services, comparing it to the Chinese thefts from Anthem, Equifax, Marriott, United Airlines and OPM [10] (**Reported**); Anthem and Equifax are covered in [Threat Actors: China](/case-studies/THREAT_ACTORS_CHINA.md).

## Part 4: impact and response

**The people.** The vendor gives no count of affected individuals [1] (**Confirmed**). The seller's figures (153M+ licenses and the rest) are the seller's [4] (**Reported**). Krebs's blank search returned about 11.5 million pages at about 15 results a page, consistent with the claim [4] (**Demonstrated**). A record count is not a count of unique people, and nobody has deduplicated it (**Inferred**). Risky Business estimates the US licenses in the set at about 63 percent of all US licenses [10] (**Reported**, author's calculation).

**The customers.** IDScan.net listed Hertz, Target, FedEx, Motorola Solutions, Jack Henry and Caesars among its clients [4] (**Reported**). Caesars and Target fell off that list (see the timeline) and Hertz did not reply [4] [6] (**Reported**).

**The vendor.** IDScan.net says it secured its systems, engaged unnamed third-party specialists, is adding security enhancements, is cooperating with regulators and law enforcement, says the notice has not been delayed by law enforcement, is not aware of misuse, and offers free credit monitoring and identity protection to US and Canadian individuals [1] (**Confirmed**). Its spokesperson called the reporting helpful to the investigation [6] (**Reported**).

**Government and regulators.** The FBI New Orleans field office opened an official investigation into an apparent breach involving idscan.net on 1 September [4], and the FBI told Reuters on 2 September it was looking into the incident [8] (**Reported**; Reuters not opened). The California AG list shows no IDScan filing as of 11 November under three spellings, while a control search returned entries [14] (**Confirmed**). No regulator or state AG enforcement action appears in any source opened; Risky Business calls for FTC attention [10] (**Reported**).

**Courts.** Nine putative class actions, per the timeline [12] (**Reported**; the dockets returned HTTP 403).

## Part 5: the defender and vulnerability-management view

- **A CVE queue would have shown nothing.** No vulnerability is in the record [1] [15]; this is a vendor data-holding risk for third-party review, not patch tracking (**Inferred**).
- **Treat ID-scan vendors as identity stores**, per the Top recommendations above [7] [13] (**Reported** advice).
- **Watch bulk reads.** Monitoring bulk API, service and administrator access is the control most likely to have shown the collection [7] (**Reported** advice; **Inferred** fit). Nearly 400,000 records added in one 24-hour period [4] is not a quiet rate (**Inferred**).
- **Retention is policy, too.** Krebs argues that no federal law limits how companies that scan licenses use, share or keep the data, and that such limits might have avoided this breach [11] (**Reported**). Caesars said it did not authorize IDScan.net to retain data from its accounts [4] (**Reported**).

### What is overstated and what is understated

- *Overstated:* Krebs's follow-up says the breach exposed license information on "more than 153 million Americans" [11]. That turns a seller's record count, which includes Canadians, into unique Americans; the vendor has confirmed no count [1] [4] (**Confirmed** for the absence; **Reported** for the figure). So is the advert's passport claim (Part 2) [5] (**Reported**).
- *Understated:* The vendor's notice omits the images, IR and UV scans and photos journalists saw [1] [4] (**Confirmed** for the omission; **Demonstrated** for the images). Its access window starts later than the seller's claim of over a year [4] (**Reported**); the 2025 scan timestamps [4] [13] point to long retention, which the notice does not discuss (**Inferred**). The national-security exposure, with senior officials' records in the set, gets little space beside the consumer framing [4] [10] (**Inferred**).

## MITRE mappings

This Part binds the record to ATT&CK v20.0 Enterprise and CAPEC, with names and tactics from the library's `data/attack/` and `data/weaknesses/` files [16]. No industrial system is involved, so no ATT&CK for ICS technique applies.

### Groups, software and campaigns

None is bound. No source names a group, malware or campaign [1] [4] [5] [10], and ATT&CK lists no object for this incident [16] (**Inferred** from the absence).

### ATT&CK Enterprise techniques

| ID | Name | Tactic(s) | Dated event or report | Sources |
|---|---|---|---|---|
| [`T1530`](/mitre/techniques/T1530.md) | Data from Cloud Storage | Collection | Unauthorized access to a portion of the vendor's cloud environment (VeriScan), 4 Apr to 2 Sep 2026; scans with timestamps later offered in Nexus | [1] [4] |
| [`T1597`](/mitre/techniques/T1597.md) | Search Closed Sources | Reconnaissance | Not observed: Nexus offered buyers search access to the records on a closed forum (listing flagged 31 Aug 2026), enabling this technique for buyers | [4] [5] |
| [`T1589`](/mitre/techniques/T1589.md) | Gather Victim Identity Information | Reconnaissance | Not observed: the records on offer (seen 1 Sep 2026) are identity information a buyer could gather; no buyer activity is in the record | [1] [4] |

Fit notes (**Inferred**): T1530 is a partial fit. The vendor says "cloud environment", not cloud storage, and names no service. T1597 and T1589 are not observed: they describe what Nexus let buyers do, and are scored as Reported context only. No initial access, credential or exfiltration technique is bound, because no source states one; T1020 Automated Exfiltration was considered for the record growth [4] and left out for that reason. T1657 Financial Theft was left out: the record shows resale, not extortion.

### CWE and CAPEC

No CVE applies, and no source states a weakness, so this study binds no CWE [1] [15]. One CAPEC entry the library relates to this study's techniques meets the record [16]:

| CAPEC | Name | Via | Where it meets the record |
|---|---|---|---|
| [CAPEC-407](/mitre/capec/CAPEC-407.md) | Pretexting | T1589 | Barracuda's advice to strengthen help-desk verification and not accept a license image alone as proof of identity [13] (**Reported** risk, not an observed event) |

CAPEC-150, which the library relates to T1530, is left out: it describes collecting from common file locations, which the record does not show.

### D3FEND countermeasures

The library maps no D3FEND countermeasure to T1530, T1589 or T1597 [16]. Two unmapped D3FEND pages describe the advised controls: [Data Inventory](/mitre/d3fend/data-inventory.md) (D3-DI), for knowing where license images are held [7], and [User Account Permissions](/mitre/d3fend/user-account-permissions.md) (D3-UAP), for limiting the service and administrator access that bulk reads need [7] (**Inferred**). The related ATT&CK mitigations are listed under Related references below [16].

### Navigator layer

The study's Navigator layer is [`navigator/library-layers/idscan-drivers-license-breach-2026.json`](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/idscan-drivers-license-breach-2026.json) ([open in Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/library-layers/idscan-drivers-license-breach-2026.json)), listed on [the Navigator layers page](/navigator/index.md). Scores: 60 primary with partial fit, 40 Reported context only; each comment names its source numbers.

## Cross-cutting themes

- **Concentration at an intermediary.** As in [Change Healthcare 2024](/case-studies/CHANGE_HEALTHCARE_2024.md) and [the Cl0p file-transfer breaches](/case-studies/CL0P_FILE_TRANSFER_2023.md), one platform in the middle of many businesses (rental counters, dispensaries and other clients [4]) set the blast radius, and the customers' own controls did not decide the outcome (**Inferred**).
- **Notices list fields; attackers sell images.** A notice that lists identifier types can be accurate and still understate harm [1] [4] (**Inferred**).

## Sources

All sources were opened on 11 November 2026.

| # | Source | URL | Opened | Grade |
|---|---|---|---|---|
| 1 | IDScan.net, Notification of Data Security Incident (posted 4 Sep 2026, updated 29 Sep 2026) | [idscan.net/notification-data-security-incident/](https://idscan.net/notification-data-security-incident/) | 2026-11-11 | Confirmed |
| 2 | IDScan.net, press release, Notification of Data Security Incident (rechecked 13 Nov 2026: the address now redirects to the notice, [1]) | [idscan.net/press-release/notification-of-data-security-incident/](https://idscan.net/press-release/notification-of-data-security-incident/) | 2026-11-11 | Confirmed |
| 3 | IDScan.net homepage (news list, product list) | [idscan.net](https://idscan.net/) | 2026-11-11 | Confirmed |
| 4 | KrebsOnSecurity, FBI Probes Service Selling 153M+ Drivers Licenses, 1 Sep 2026, updated 2 and 8 Sep | [krebsonsecurity.com/2026/09/fbi-probes-service-selling-153m-drivers-licenses/](https://krebsonsecurity.com/2026/09/fbi-probes-service-selling-153m-drivers-licenses/) | 2026-11-11 | Reported |
| 5 | TechCrunch, report that hackers appear to have breached a major ID card verification service, 2 Sep 2026 | [techcrunch.com/2026/09/02/...](https://techcrunch.com/2026/09/02/it-sure-looks-like-hackers-breached-a-major-id-card-verification-service/) | 2026-11-11 | Reported |
| 6 | Techlicious, report on the FBI probe of the breach tied to 153 million stolen driver's licenses, 2 Sep 2026, updated 3 Sep | [techlicious.com/blog/...](https://www.techlicious.com/blog/fbi-probes-breach-tied-to-153-million-stolen-drivers-licenses/) | 2026-11-11 | Reported |
| 7 | NCC Group, news reaction to reports of 153 million driver's licence scans linked to IDScan.net, 3 Sep 2026 | [nccgroup.com/newsroom/...](https://www.nccgroup.com/newsroom/news-reaction-reports-of-153-million-drivers-licence-scans-linked-to-idscannet/) | 2026-11-11 | Reported |
| 8 | eSecurity Planet, report on the FBI and the dark-web sale of 153 million driver's licenses, 3 Sep 2026 | [esecurityplanet.com/threats/...](https://www.esecurityplanet.com/threats/news-fbi-dark-web-153-million-drivers-licenses/) | 2026-11-11 | Reported |
| 9 | Help Net Security, report on the IDScan.net data breach, 11 Sep 2026 | [helpnetsecurity.com/2026/09/11/...](https://www.helpnetsecurity.com/2026/09/11/idscan-net-data-breach-153-million-drivers-licenses/) | 2026-11-11 | Reported |
| 10 | Risky Business newsletter (Srsly Risky Biz), on the driver's licence breach as a national security problem, 10 Sep 2026 | [risky.biz/srsly-risky-biz-...](https://risky.biz/srsly-risky-biz-americas-drivers-licence-breach-is-a-national-security-disaster/) | 2026-11-11 | Reported |
| 11 | KrebsOnSecurity, report on data broker Radaris losing domains in a privacy fight, 16 Sep 2026 | [krebsonsecurity.com/2026/09/data-broker-radaris-...](https://krebsonsecurity.com/2026/09/data-broker-radaris-loses-domains-in-privacy-fight/) | 2026-11-11 | Reported |
| 12 | Zyphe, roundup of the IDScan data breach class actions, September 2026 | [zyphe.com/resources/news/...](https://www.zyphe.com/resources/news/idscan-data-breach-class-actions-september-2026) | 2026-11-11 | Reported |
| 13 | Barracuda blog, analysis of the IDScan data breach, 20 Oct 2026 | [blog.barracuda.com/2026/10/20/...](https://blog.barracuda.com/2026/10/20/idscan-data-breach-drivers-license) | 2026-11-11 | Reported |
| 14 | California Attorney General, data breach list, organization search for IDScan (with ID Scan and IDscan.net, and a control search) | [oag.ca.gov/privacy/databreach/list?...IDScan](https://oag.ca.gov/privacy/databreach/list?field_sb24_org_name_value=IDScan) | 2026-11-11 | Confirmed |
| 15 | Team Star Wolf Intelligence Hub, feed.json and the v7 KEV and 2026 history shards (one Risky Business row, no KEV row) | [teamstarwolf.github.io/intelligence-hub/data/feed.json](https://teamstarwolf.github.io/intelligence-hub/data/feed.json) | 2026-11-11 | Confirmed |
| 16 | TeamStarWolf library data: `data/attack/technique_profiles.jsonl`, `mitigation_to_technique.jsonl`, `technique_to_d3fend.jsonl`, `d3fend_countermeasures.jsonl`, `data/weaknesses/capec.jsonl` and the `mitre/` tree | [github.com/TeamStarWolf/TeamStarWolf/tree/main/data](https://github.com/TeamStarWolf/TeamStarWolf/tree/main/data) | 2026-11-11 | Confirmed |

Not opened, so not cited as sources: the Reuters report of 2 September 2026, the class-action dockets on CourtListener (HTTP 403), the Maine and Vermont AG breach lists, the Texas AG breach portal, any FTC or state AG enforcement record, a fresh NVD or CISA search, the Exploit forum and the Nexus service, which this study does not visit.

*© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.*

*© The MITRE Corporation. Includes material from the Common Weakness Enumeration (CWE™), used under the CWE Terms of Use. https://cwe.mitre.org/*

*© The MITRE Corporation. Includes material from the Common Attack Pattern Enumeration and Classification (CAPEC™), used under the CAPEC Terms of Use. https://capec.mitre.org/*

*© The MITRE Corporation. Includes material from MITRE D3FEND™, used under the D3FEND Terms of Use. https://d3fend.mitre.org/*

*The terms for every MITRE dataset used here are recorded in [THIRD_PARTY_NOTICES.md](/THIRD_PARTY_NOTICES.md).*

## Related references

- [The Year 2026 in Intrusions](/case-studies/CHRONICLE_2026.md), [Change Healthcare 2024](/case-studies/CHANGE_HEALTHCARE_2024.md), [The Cl0p File-Transfer Breaches](/case-studies/CL0P_FILE_TRANSFER_2023.md), [Threat Actors: China](/case-studies/THREAT_ACTORS_CHINA.md)
- [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [Notable Incidents](/NOTABLE_INCIDENTS.md)
- [CVE Reference](/CVE_REFERENCE.md), [CWE Reference](/CWE_REFERENCE.md), [CAPEC Reference](/CAPEC_REFERENCE.md), [D3FEND Reference](/D3FEND_REFERENCE.md)
- [Data Security Reference](/DATA_SECURITY_REFERENCE.md), [Privacy Engineering Reference](/PRIVACY_ENGINEERING_REFERENCE.md), [Cloud Security Reference](/CLOUD_SECURITY_REFERENCE.md), [API Security Reference](/API_SECURITY_REFERENCE.md), [Identity Security Reference](/IDENTITY_SECURITY_REFERENCE.md), [Social Engineering Reference](/SOCIAL_ENGINEERING_REFERENCE.md), [Fraud Framework Reference](/FRAUD_FRAMEWORK_REFERENCE.md), [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md), [Threat Intelligence Reference](/THREAT_INTELLIGENCE_REFERENCE.md)
- [Vulnerability Prioritization Reference](/VULNERABILITY_PRIORITIZATION_REFERENCE.md), [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md)
- Techniques: [T1530 Data from Cloud Storage](/mitre/techniques/T1530.md), [T1597 Search Closed Sources](/mitre/techniques/T1597.md), [T1589 Gather Victim Identity Information](/mitre/techniques/T1589.md)
- Mitigations: [M1047 Audit](/mitre/mitigations/M1047.md), [M1041 Encrypt Sensitive Information](/mitre/mitigations/M1041.md), [M1022 Restrict File and Directory Permissions](/mitre/mitigations/M1022.md), [M1018 User Account Management](/mitre/mitigations/M1018.md), [M1032 Multi-factor Authentication](/mitre/mitigations/M1032.md), [M1037 Filter Network Traffic](/mitre/mitigations/M1037.md), [M1056 Pre-compromise](/mitre/mitigations/M1056.md)
- CAPEC: [CAPEC-407 Pretexting](/mitre/capec/CAPEC-407.md); D3FEND: [Data Inventory](/mitre/d3fend/data-inventory.md), [User Account Permissions](/mitre/d3fend/user-account-permissions.md)
- [Navigator layers](/navigator/index.md), including this study's layer, [idscan-drivers-license-breach-2026.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/idscan-drivers-license-breach-2026.json)
- The [Team Star Wolf Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/)
- [All case studies](/case-studies/README.md)
