# The DentaQuest Health-Data Breach of May 2026: A Case Study

*A TeamStarWolf case study. Published 11 November 2026; every source checked as of that date.*

[All case studies](/case-studies/README.md) · Related: [Healthcare Threat Watchlist](/case-studies/HEALTHCARE_THREAT_WATCHLIST.md), [Change Healthcare 2024](/case-studies/CHANGE_HEALTHCARE_2024.md), [The Cl0p File-Transfer Breaches](/case-studies/CL0P_FILE_TRANSFER_2023.md), [Notable Incidents](/NOTABLE_INCIDENTS.md), [Healthcare Security Reference](/HEALTHCARE_SECURITY_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Healthcare and health-plan security leaders, identity and access teams, detection engineers, privacy and breach-response staff and vulnerability management leads

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 16 min (3,588 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want the dated record of the May 2026 DentaQuest breach, why its counts disagree, or which identity and data controls the case argues for

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [Part 1: what happened](#part-1-what-happened), [Part 5: the defender and vulnerability-management view](#part-5-the-defender-and-vulnerability-management-view)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Healthcare Security Reference](/HEALTHCARE_SECURITY_REFERENCE.md), [Social Engineering Reference](/SOCIAL_ENGINEERING_REFERENCE.md), [Identity Security Reference](/IDENTITY_SECURITY_REFERENCE.md), [Healthcare Threat Watchlist](/case-studies/HEALTHCARE_THREAT_WATCHLIST.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive summary

The people in this breach are current and former dental and vision plan members, including Medicaid and Medicare enrollees, children and people who have died [1] [4] (**Confirmed**). In July 2026 DentaQuest told regulators that more than 15 million people's protected health information was accessed [1], and filed separate letters for adults, minors and deceased individuals [4] (**Confirmed**). On the 11 November HHS breach portal export, 15,000,000 is the year's largest entry [8] (**Confirmed**).

The intrusion was short and needed no malware. Per DentaQuest's counsel, social engineering got one employee to hand over credentials and a multifactor authentication code; from 17 to 19 May 2026 the actor took data from a network file share; forensics found no malware, privilege escalation or other compromised accounts [1] (**Confirmed** as the victim's statement to a regulator). DentaQuest learned of it on 20 May, when a third party claimed to hold its data [1] (**Confirmed**).

ShinyHunters claimed the theft and published the data [14] (**Reported**); DentaQuest's filings never name the actor [1] (**Confirmed**). No CVE or KEV entry applies: this was an identity failure, not a software flaw (**Inferred** from [1]).

### Key facts at a glance

| Field | Value |
|---|---|
| Victim | DentaQuest, LLC, a health plan in Massachusetts on the HHS portal [8] (**Confirmed**); part of Sun Life U.S. Dental, owned by Sun Life Financial [14] (**Reported**) |
| Intrusion window | 17 to 19 May 2026 per counsel and Oregon [1] [6]; "ended by May 20" per DentaQuest's consumer notice [2] (**Confirmed**; the victim's documents disagree) |
| Entry vector | Social engineering of one employee for credentials and an MFA code; channel (phone or email) not stated [1] (**Confirmed**) |
| Systems affected | Data exfiltrated from a network file share; operating systems not affected [1] (**Confirmed**) |
| People affected | 15,000,000 per HHS [8] and Oregon [6]; "more than 15 million" per counsel [1] (**Confirmed**) |
| Claimed by | ShinyHunters, about 234 GB claimed [14] (**Reported**); listed as "Claimed Actor" in an Indiana state brief [9] (**Confirmed** as Indiana's listing of a claim) |
| ATT&CK group (context only) | [G1057 ShinyHunters](/mitre/groups/G1057.md); ATT&CK does not list DentaQuest [23] (**Confirmed**) |
| CVE and KEV | None applies [1] [12] (**Inferred**) |
| Regulator status | Under HHS OCR investigation [8] (**Confirmed**) |

### Key findings

- **One employee and one code were enough.** Counsel's letter puts the entire entry on a single employee who gave up credentials and an MFA code [1] (**Confirmed**). A code a person can read out is phishable by design (**Inferred**).
- **The victim learned from the extortionist.** Activity ended on 19 May; DentaQuest "became aware of" a third party claiming to hold its data on 20 May [1] (**Confirmed**). Nothing in the record shows internal detection (**Inferred**).
- **A file share held years of enrollment data.** Much of the leak was ASC X12 enrollment files, some with Medicaid IDs [13], and reportedly reaches back to at least 2009 [16] [17] (**Reported**). Retention and share scope, not exploit code, set the size of this breach (**Inferred**).
- **The headline numbers disagree, and only one is a regulator count.** 15,000,000 is the figure filed with HHS and the states [1] [6] [8] (**Confirmed**); 2.6 million counts email addresses in the leak [13]; 23.4 million is a third party's dedupe of name and date-of-birth pairs, about two thirds already in earlier breach corpora [21] (**Reported**).

### Top recommendations

1. Move staff with access to member data to phishing-resistant MFA [1] (**Inferred** from the entry vector).
2. Scope and age-out enrollment file shares; files reportedly dating to 2009 [16] should not sit on a share a single user can bulk-read (**Inferred**).
3. Alert on bulk file-share reads and large outbound transfers, so the first signal is not an extortion message [1] (**Inferred**).
4. Plan notification for minors and decedents before an incident [4] (**Inferred**).

## Scope and method

This brief covers the May 2026 DentaQuest intrusion, its attribution, the count dispute and the response through 11 November 2026. The sector picture is in the [Healthcare Threat Watchlist](/case-studies/HEALTHCARE_THREAT_WATCHLIST.md) [24]. Tradecraft is described at advisory level; the actor's leak site was not visited.

| Grade | Meaning in this study |
|---|---|
| Confirmed | Stated in a primary opened for this study: victim filings and notices, government listings and briefs, a company release, ATT&CK or library data. A victim's account of its own investigation is Confirmed as that victim's statement |
| Reported | Journalism, third-party analysis (including Have I Been Pwned), the actor's claims, or a secondary account of an unopened primary |
| Demonstrated | Not used: no lab work or reproduction applies to this incident |
| Inferred | This study's own reasoning from cited facts, labelled where it appears |

## Part 1: what happened

| Date (2026) | Event | Sources | Grade |
|---|---|---|---|
| 17 to 19 May | After one employee is socially engineered, the actor accesses a limited portion of the network and exfiltrates data from a file share; activity ends 19 May | [1] [4] [6] | Confirmed |
| 20 May | DentaQuest becomes aware of a third party claiming to hold its data; containment the same day | [1] | Confirmed |
| 20 May | Per DentaQuest's July consumer notice, it "discovered" the access on 20 May and the incident "ended by May 20, 2026" | [2] | Confirmed (conflicts with [1] [6]) |
| 29 May | DentaQuest learns the data was posted on the dark web | [1] | Confirmed |
| 30 May | ShinyHunters leak-site post last updated: about 234 GB, 2.6 million people, DentaQuest "failed to reach an agreement" | [14] | Reported |
| 3 June | Have I Been Pwned adds 2.6 million unique email addresses | [13] | Reported |
| 29 June | Kroll gives DentaQuest initial information on impacted individuals | [1] | Confirmed |
| 16 July | Counsel notifies the Rhode Island AG of more than 15 million people; HHS OCR (15,000,000, Hacking/IT Incident, Network Server), California and Oregon listings dated the same day | [1] [4] [6] [8] | Confirmed |
| 17 July | Individual notification by mail begins | [1] [2] | Confirmed |
| 23 to 27 July | Trade press reports a 23 million estimate; SecurityWeek counts letters to at least 4.5 million people in three states' filings | [16] [17] [18] | Reported |
| 11 November | HHS export: 15,000,000 is the largest 2026 entry, ahead of Aesto (9,540,683) and iRhythm Technologies (8,179,772) | [8] | Confirmed |

## Part 2: the intrusion record

The mechanism of the intrusion comes from one document: counsel's 16 July letter to the Rhode Island Attorney General [1] (**Confirmed**). It says social engineering tricked a single employee into providing credentials and a multifactor authentication code, in violation of company policy. CrowdStrike Services found no other compromised accounts, no malware or ransomware, no privilege escalation and no added persistence, and operating systems were not affected [1] (**Confirmed**).

The letter does not say whether the lure came by phone or by email, what kind of MFA was in use, which remote-access path the actor used with the stolen credentials, or how the data left the network [1] (**Confirmed** as absences), so no lure sub-technique or exfiltration channel is bound.

Much of the leaked data is enrollment data. Counsel's letter says the impacted data included names, dates of birth, Social Security numbers, Medicare and Medicaid identification numbers, health plan numbers and dental and vision information such as diagnosis, treatment and billing [1] (**Confirmed**). Have I Been Pwned adds addresses, phone numbers, genders and government IDs, much of it in ASC X12 enrollment files, some carrying Medicaid IDs [13] (**Reported**). HIPAA Journal and Security Affairs report a folder of more than 1.7 million SSNs a researcher ties largely to Texas children, and files back to at least 2009 [16] [17] (**Reported**). DentaQuest's separate letters for minors and deceased individuals [4] confirm that children and decedents were in scope (**Confirmed**).

Containment came on 20 May, and monitoring since has found no further threat actor activity [1] (**Confirmed**); systems stayed operational throughout [14] [19] (**Reported**). The record names no patch and no product version because there was nothing to patch [1] [12] (**Inferred**).

## Part 3: who and why

Attribution here is a claim.

- **The victim.** DentaQuest's filings and notices call the attacker only a "Threat Actor" or an unauthorized third party and never name a group [1] [2] (**Confirmed**).
- **The claimant.** ShinyHunters claimed about 234 GB on its leak site and said DentaQuest "failed to reach an agreement" [14]; Security Affairs and Have I Been Pwned describe pay-or-leak extortion [13] [15] (**Reported**).
- **State government.** Indiana's August brief lists "Claimed Actor: ShinyHunters" and financial extortion [9] (**Confirmed** as Indiana's listing; the attribution is still a claim).
- **Federal government.** The FBI's 15 May PSA on ShinyHunters covers an education-sector attack and does not name DentaQuest or healthcare [10] (**Confirmed**); no federal advisory naming DentaQuest was found.
- **ATT&CK.** [G1057 ShinyHunters](/mitre/groups/G1057.md) is a criminal collective that gathers credentials and PII for resale or extortion, tied to "The Com" alongside [G1015 Scattered Spider](/mitre/groups/G1015.md) and [G1004 LAPSUS$](/mitre/groups/G1004.md) [23] (**Confirmed** as ATT&CK's description). ATT&CK does not list DentaQuest under G1057 or the [C0059 Salesforce Data Exfiltration](/mitre/campaigns/C0059.md) campaign, whose CRM pattern a file share does not match [23] (**Inferred**). Both links are context, not attribution.

Every source that states a motive says money [9] [14] [15] (**Reported** and **Confirmed** as marked above). The data's resale value is high and lasting: Social Security numbers, especially children's, are rarely reissued, and Medicaid and government IDs change slowly (**Inferred**).

## Part 4: impact and response

**The people.** More than 15 million individuals' PHI was accessed, per DentaQuest [1]; HHS and Oregon list 15,000,000 [6] [8] (**Confirmed**). The Kroll review was still ongoing on 16 July, so the figure is a floor [1] (**Inferred** from [1]). DentaQuest serves about 32 million Americans per ISMG [14], or 35 million per SecurityWeek [18] (**Reported**).

**The company.** DentaQuest engaged CrowdStrike Services and Kroll, informed the FBI on 21 May, and offered 24 months of Kroll identity monitoring and restoration [1] [2] [5] (**Confirmed**). It says it has since added security measures, monitoring and employee training [2] [5] (**Confirmed** as DentaQuest's statement). Its holding statement, last updated 18 June, remains on dentaquest.com and warns members about targeted scams [3] (**Confirmed**). Sun Life's 6 August Q2 release discloses no incident or cost [11] (**Confirmed**).

**Regulators.** DentaQuest notified HHS OCR, gave HIPAA substitute and media notice, and notified the credit bureaus [1] (**Confirmed**). Filings sit with the Rhode Island AG [1], California AG [4] [5], Oregon DOJ [6] and South Carolina [7] (**Confirmed**); Texas and Massachusetts filings are reported [18] (**Reported**; not opened). HHS OCR lists the breach as under investigation [8] (**Confirmed**). On 1 August ISMG still saw only a separate 3,086-person DentaQuest entry on the portal [19] (**Reported**), so the 16 July submission was posted later (**Inferred**).

**Courts.** Whitlow v. DentaQuest Group Inc. et al. (D. Mass.) is reported as filed on 4 June, alleging negligence and delayed notice [22] (**Reported**; docket not checked).

**KEV and CVE.** The Intelligence Hub feed and its May to August 2026 shards carry no DentaQuest row [12] (**Confirmed**; **Inferred** that none should, since no software vulnerability is in the record).

## Part 5: the defender and vulnerability-management view

- **A CVE queue would have shown nothing.** The exposure was an identity control and a retention decision [1] (**Inferred**).
- **Treat code-based MFA as phishable.** Phishing-resistant MFA for anyone who can reach member data, plus identity checks on help-desk and reset paths, removes the code a caller can collect [1] (**Inferred**).
- **Shrink one account's blast radius.** A single user reached a share holding enrollment files reportedly back to 2009 [1] [16] (**Confirmed** for the share; **Reported** for the age). Least-privilege share permissions, retention limits on X12 extracts and data loss prevention on bulk reads follow (**Inferred**).
- **Detect the theft, not the ransom note.** Three days of access ended before DentaQuest knew [1] (**Confirmed**); file-share enumeration and large-transfer alerts would have signalled earlier (**Inferred**).

### What is overstated and what is understated

- *Overstated:* "23 million affected" is a researcher's dedupe of name and date-of-birth pairs, not a regulator figure [16] [21] (**Reported**). "ShinyHunters breached DentaQuest" stated as fact goes beyond the record: the victim names no actor [1], and Indiana calls it a claim [9] (**Confirmed**). Linking the incident to the Salesforce campaign C0059 overreaches [1] [23] (**Inferred**).
- *Understated:* "2.6 million" counts email addresses, not people [13] [21] (**Reported**); the regulator figure is 15,000,000 [8] (**Confirmed**). The age of the data, reportedly back to 2009 [16] [17], and the children's records [4] [16] get less attention than the headline count (**Inferred**). The victim's own documents disagree on the end date, 19 May [1] [6] against "by May 20" [2] (**Confirmed**).

## MITRE mappings

This Part binds the verified record to ATT&CK v20.0 Enterprise, CAPEC and D3FEND, with names and tactics from the library's `data/attack/` files [23]. No source describes industrial systems, so no ATT&CK for ICS techniques apply. Rows rest on counsel's letter [1] unless marked.

### Groups, software and campaigns

| Object | ATT&CK id | Relationship to this record |
|---|---|---|
| ShinyHunters | [G1057](/mitre/groups/G1057.md) | Context only: the claimant [13] [14] [15] |
| Scattered Spider, LAPSUS$ | [G1015](/mitre/groups/G1015.md), [G1004](/mitre/groups/G1004.md) | Context only: "The Com" in ATT&CK's G1057 description [23] |
| Salesforce Data Exfiltration | [C0059](/mitre/campaigns/C0059.md) | Context only: a different pattern (CRM data theft) [23] |

No software is bound: the investigation found no malware [1].

### ATT&CK Enterprise techniques

| ID | Name | Tactic(s) | Dated event or report | Sources |
|---|---|---|---|---|
| [`T1598`](/mitre/techniques/T1598.md) | Phishing for Information | Reconnaissance | Social engineering tricked one employee into giving credentials and an MFA code, from 17 May 2026; channel not stated | [1] |
| [`T1111`](/mitre/techniques/T1111.md) | Multi-Factor Authentication Interception | Credential Access | MFA code obtained from the employee, from 17 May 2026 | [1] |
| [`T1078`](/mitre/techniques/T1078.md) | Valid Accounts | Initial Access, Persistence, Privilege Escalation, Stealth | The employee's credentials gave access to a limited portion of the network, 17 to 19 May 2026 | [1] [6] |
| [`T1039`](/mitre/techniques/T1039.md) | Data from Network Shared Drive | Collection | Data accessed and exfiltrated from a network file share, 17 to 19 May 2026 | [1] |
| [`T1657`](/mitre/techniques/T1657.md) | Financial Theft | Impact | Leak-site post (last updated 30 May 2026) says DentaQuest "failed to reach an agreement"; Indiana lists financial extortion | [9] [14] [15] |

Fit notes (**Inferred**): T1078 and T1039 fit the counsel letter directly. T1598 gets no sub-technique because the lure channel is not stated. T1111 is a partial fit: the employee handed the code over rather than having it intercepted. T1657, whose ATT&CK description covers extortion, rests on the actor's claim and Indiana's label. No exfiltration technique, T1684.001 Impersonation or T1621 Multi-Factor Authentication Request Generation is bound, because the record describes none of them.

### CWE and CAPEC

No CVE applies, so this study binds no CWE [1]. CAPEC entries the library relates to this study's techniques [23]:

| CAPEC | Name | Via | Where it meets the record |
|---|---|---|---|
| [CAPEC-98](/mitre/capec/CAPEC-98.md) | Phishing | T1598 | The social engineering of one employee for credentials and an MFA code [1] |
| [CAPEC-560](/mitre/capec/CAPEC-560.md) | Use of Known Domain Credentials | T1078 | Use of the employee's credentials to reach the network [1] (**Inferred**, partial fit) |

CAPEC-639, CAPEC-158, CAPEC-609 and CAPEC-651 are left out: the record describes none of their behaviors.

### D3FEND countermeasures

| D3FEND countermeasure | Techniques the library maps it to (from this study) | Where it meets the record |
|---|---|---|
| [User Account Permissions](/mitre/d3fend/user-account-permissions.md) (D3-UAP) | T1078 | One employee's account reached a file share of member data [1] |
| [Access Modeling](/mitre/d3fend/access-modeling.md) (D3-AM) | T1078 | Knowing which identities can read which shares [1] (**Inferred**) |
| [Account Locking](/mitre/d3fend/account-locking.md) (D3-AL) | T1078 | Containment on 20 May; method not stated [1] (**Inferred**) |
| [Network Resource Access Mediation](/mitre/d3fend/network-resource-access-mediation.md) (D3-NRAM) | T1039 | Mediating access to the file share [1] |
| [Decoy Network Resource](/mitre/d3fend/decoy-network-resource.md) (D3-DNR) | T1039 | A decoy share could give the internal signal the record lacks [1] (**Inferred**) |

[Multi-factor Authentication](/mitre/d3fend/multi-factor-authentication.md) (D3-MFA), in phishing-resistant forms, is what the entry vector points to, though the library does not map it to these techniques. Related mitigations: [M1032 Multi-factor Authentication](/mitre/mitigations/M1032.md), [M1017 User Training](/mitre/mitigations/M1017.md), [M1022 Restrict File and Directory Permissions](/mitre/mitigations/M1022.md) and [M1057 Data Loss Prevention](/mitre/mitigations/M1057.md). See the [D3FEND Reference](/D3FEND_REFERENCE.md).

### Navigator layer

The study's Navigator layer is [`navigator/library-layers/dentaquest-breach-2026.json`](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/dentaquest-breach-2026.json) ([open in Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/library-layers/dentaquest-breach-2026.json)), listed on [the Navigator layers page](/navigator/index.md). It is pinned to ATT&CK v20 Enterprise; scores measure the tie to this record (100 direct fit to a primary, 60 primary with partial fit, 40 Reported only), and each comment names its source numbers.

## Cross-cutting themes

- **Identity is the perimeter for data theft.** As in [Change Healthcare 2024](/case-studies/CHANGE_HEALTHCARE_2024.md), a weak authentication step opened a healthcare intermediary; here no ransomware followed [1] (**Inferred**).
- **Extortion without encryption.** DentaQuest kept running while its data was published, as in [the Cl0p file-transfer breaches](/case-studies/CL0P_FILE_TRANSFER_2023.md) [1] [14] (**Inferred**).
- **Counts are contested by design.** Actors inflate, analysts count emails or deduped pairs, and victims file a floor [1] [13] [14] [21] (**Inferred**). Cite the regulator figure and say what the others measure.
- **Old data is live risk.** Files reportedly from 2009 [16] and children's SSNs [16] [17] outlast any monitoring offer (**Inferred**).

## Sources

All sources were opened on 11 November 2026.

| # | Source | URL | Opened | Grade |
|---|---|---|---|---|
| 1 | DentaQuest LLC, notice of data security incident to the Rhode Island Attorney General: outside counsel's cover letter of 16 Jul 2026 with enclosed consumer letters | [riag.ri.gov/media/8956/download](https://riag.ri.gov/media/8956/download) | 2026-11-11 | Confirmed |
| 2 | DentaQuest, Notice of Data Breach (substitute notice), 16 Jul 2026 | [dentaquest.com/en/security-update-0526](https://www.dentaquest.com/en/security-update-0526) | 2026-11-11 | Confirmed |
| 3 | DentaQuest, Update on Cybersecurity Incident (holding statement) | [dentaquest.com/it/security-update-0526](https://www.dentaquest.com/it/security-update-0526) | 2026-11-11 | Confirmed |
| 4 | California Attorney General, data breach list entry for DentaQuest LLC (breach 05/17/2026, reported 07/16/2026; adult, minor and deceased letters) | [oag.ca.gov/privacy/databreach/list?...DentaQuest](https://oag.ca.gov/privacy/databreach/list?field_sb24_org_name_value=DentaQuest) | 2026-11-11 | Confirmed |
| 5 | California Attorney General, DentaQuest Adult Notification Letter | [oag.ca.gov/system/files/DentaQuest - Adult Notification Letter.pdf](https://oag.ca.gov/system/files/DentaQuest%20-%20Adult%20Notification%20Letter.pdf) | 2026-11-11 | Confirmed |
| 6 | Oregon Department of Justice, consumer data breach list entry for DentaQuest LLC | [justice.oregon.gov/consumer/DataBreach/](https://justice.oregon.gov/consumer/DataBreach/) | 2026-11-11 | Confirmed |
| 7 | South Carolina Department of Consumer Affairs, DentaQuest LLC consumer letter filing | [consumer.sc.gov/.../Consumer Letter - DentaQuest LLC.pdf](https://consumer.sc.gov/sites/consumer/files/Documents/Security%20Breach%20Notices/2026/Consumer%20Letter%20-%20DentaQuest%20LLC.pdf) | 2026-11-11 | Confirmed |
| 8 | HHS Office for Civil Rights, breach portal (cases under investigation, export) | [ocrportal.hhs.gov/ocr/breach/breach_report.jsf](https://ocrportal.hhs.gov/ocr/breach/breach_report.jsf) | 2026-11-11 | Confirmed |
| 9 | Indiana Executive Council on Cybersecurity, Healthcare Cyber Risk Brief, August 2026 | [in.gov/cybersecurity/...August 2026.pdf](https://www.in.gov/cybersecurity/IECC%20Healthcare_Healthcare%20Cyber%20Risk%20Brief_August%202026.pdf) | 2026-11-11 | Confirmed |
| 10 | FBI IC3, Public Service Announcement I-051526-PSA, 15 May 2026 | [ic3.gov/PSA/2026/PSA260515](https://www.ic3.gov/PSA/2026/PSA260515) | 2026-11-11 | Confirmed |
| 11 | Sun Life, second quarter 2026 results release, 6 Aug 2026 | [sunlife.com/en/investors/financial-news/...](https://www.sunlife.com/en/investors/financial-news/announcement/sun-life-reports-second-quarter-2026-results/124117/) | 2026-11-11 | Confirmed |
| 12 | Team Star Wolf Intelligence Hub, feed.json and the 2026-05 to 2026-08 v7 shards (no DentaQuest row) | [teamstarwolf.github.io/intelligence-hub/data/feed.json](https://teamstarwolf.github.io/intelligence-hub/data/feed.json) | 2026-11-11 | Confirmed |
| 13 | Have I Been Pwned, DentaQuest breach entry, added 3 Jun 2026 | [haveibeenpwned.com/breach/DentaQuest](https://haveibeenpwned.com/breach/DentaQuest) | 2026-11-11 | Reported |
| 14 | ISMG GovInfoSecurity, ShinyHunters leaks 234GB DentaQuest data trove, 4 Jun 2026 | [govinfosecurity.com/...-a-31883](https://www.govinfosecurity.com/shinyhunters-leaks-234gb-dentaquest-data-trove-a-31883) | 2026-11-11 | Reported |
| 15 | Security Affairs, DentaQuest breach: ShinyHunters publish data impacting 2.6M people, 7 Jun 2026 | [securityaffairs.com/193274/...](https://securityaffairs.com/193274/data-breach/dentaquest-breach-shinyhunters-publish-data-impacting-2-6m-people.html) | 2026-11-11 | Reported |
| 16 | The HIPAA Journal, DentaQuest data breach, 23 Jul 2026 | [hipaajournal.com/dentaquest-data-breach/](https://www.hipaajournal.com/dentaquest-data-breach/) | 2026-11-11 | Reported |
| 17 | Security Affairs, DentaQuest disclosed a data breach that impacted 23 million individuals, 27 Jul 2026 | [securityaffairs.com/?p=196100](https://securityaffairs.com/?p=196100) | 2026-11-11 | Reported |
| 18 | SecurityWeek, DentaQuest data breach potentially impacts over 23 million people, 27 Jul 2026 | [securityweek.com/...](https://www.securityweek.com/dentaquest-data-breach-potentially-impacts-over-23-million-people/) | 2026-11-11 | Reported |
| 19 | ISMG BankInfoSecurity, DentaQuest data theft hack affects 15M patients, 31 Jul 2026, updated 1 Aug | [bankinfosecurity.com/...-a-32390](https://www.bankinfosecurity.com/dentaquest-data-theft-hack-affects-15m-patients-a-32390) | 2026-11-11 | Reported |
| 20 | The HIPAA Journal, July 2026 healthcare data breach report | [hipaajournal.com/july-2026-healthcare-data-breach-report/](https://www.hipaajournal.com/july-2026-healthcare-data-breach-report/) | 2026-11-11 | Reported |
| 21 | Paubox, DentaQuest breach toll passes 23 million as notifications begin, 5 Aug 2026 | [paubox.com/blog/...](https://www.paubox.com/blog/dentaquest-breach-toll-passes-23-million-as-notifications-begin) | 2026-11-11 | Reported |
| 22 | Top Class Actions, DentaQuest sued for allegedly exposing 15M patients' private information | topclassactions.com, path /lawsuit-settlements/lawsuit-news/dentaquest-sued-for-allegedly-exposing-15m-patients-private-information/ (not linked: the site refuses automated link checkers; it opened in a browser-identified request on 13 November 2026) | 2026-11-11 | Reported |
| 23 | TeamStarWolf library data: `data/attack/technique_profiles.jsonl`, `groups.jsonl`, `group_to_technique.jsonl`, `campaigns.jsonl`, `technique_to_d3fend.jsonl`, `d3fend_countermeasures.jsonl`, `data/weaknesses/capec.jsonl` and the `mitre/` tree, including the G1057 page | [github.com/TeamStarWolf/TeamStarWolf/tree/main/data](https://github.com/TeamStarWolf/TeamStarWolf/tree/main/data) | 2026-11-11 | Confirmed |
| 24 | TeamStarWolf library, Healthcare Threat Watchlist | [/case-studies/HEALTHCARE_THREAT_WATCHLIST.md](/case-studies/HEALTHCARE_THREAT_WATCHLIST.md) | 2026-11-11 | Confirmed |

Not opened, so not cited as sources: the Massachusetts Office of Consumer Affairs filing 2026-1155 (HTTP 403), the Texas and Indiana Attorney General listings, the Whitlow docket on PACER, the original 1 June DentaQuest page in its first form, and the actor's leak site, which this study does not visit. The HIPAA Journal July report [20] is listed for its account of the HHS row, which [8] now confirms directly.

*© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.*

*© The MITRE Corporation. Includes material from the Common Weakness Enumeration (CWE™), used under the CWE Terms of Use. https://cwe.mitre.org/*

*© The MITRE Corporation. Includes material from the Common Attack Pattern Enumeration and Classification (CAPEC™), used under the CAPEC Terms of Use. https://capec.mitre.org/*

*© The MITRE Corporation. Includes material from MITRE D3FEND™, used under the D3FEND Terms of Use. https://d3fend.mitre.org/*

*The terms for every MITRE dataset used here are recorded in [THIRD_PARTY_NOTICES.md](/THIRD_PARTY_NOTICES.md).*

## Related references

- [Healthcare Threat Watchlist](/case-studies/HEALTHCARE_THREAT_WATCHLIST.md), [Change Healthcare 2024](/case-studies/CHANGE_HEALTHCARE_2024.md), [The Cl0p File-Transfer Breaches](/case-studies/CL0P_FILE_TRANSFER_2023.md)
- [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [Notable Incidents](/NOTABLE_INCIDENTS.md)
- [CVE Reference](/CVE_REFERENCE.md), [CWE Reference](/CWE_REFERENCE.md), [CAPEC Reference](/CAPEC_REFERENCE.md), [D3FEND Reference](/D3FEND_REFERENCE.md)
- [Social Engineering Reference](/SOCIAL_ENGINEERING_REFERENCE.md), [Identity Security Reference](/IDENTITY_SECURITY_REFERENCE.md), [Identity and Access Management Reference](/IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md), [Data Security Reference](/DATA_SECURITY_REFERENCE.md), [Privacy Engineering Reference](/PRIVACY_ENGINEERING_REFERENCE.md), [Healthcare Security Reference](/HEALTHCARE_SECURITY_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md), [Ransomware Defense Reference](/RANSOMWARE_DEFENSE_REFERENCE.md)
- [Vulnerability Prioritization Reference](/VULNERABILITY_PRIORITIZATION_REFERENCE.md), [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md)
- Groups and campaign (context only): [G1057 ShinyHunters](/mitre/groups/G1057.md), [G1015 Scattered Spider](/mitre/groups/G1015.md), [G1004 LAPSUS$](/mitre/groups/G1004.md), [C0059 Salesforce Data Exfiltration](/mitre/campaigns/C0059.md)
- Techniques: [T1598 Phishing for Information](/mitre/techniques/T1598.md), [T1111 Multi-Factor Authentication Interception](/mitre/techniques/T1111.md), [T1078 Valid Accounts](/mitre/techniques/T1078.md), [T1039 Data from Network Shared Drive](/mitre/techniques/T1039.md), [T1657 Financial Theft](/mitre/techniques/T1657.md)
- Mitigations: [M1032 Multi-factor Authentication](/mitre/mitigations/M1032.md), [M1017 User Training](/mitre/mitigations/M1017.md), [M1022 Restrict File and Directory Permissions](/mitre/mitigations/M1022.md), [M1057 Data Loss Prevention](/mitre/mitigations/M1057.md)
- CAPEC: [CAPEC-98](/mitre/capec/CAPEC-98.md), [CAPEC-560](/mitre/capec/CAPEC-560.md)
- [Navigator layers](/navigator/index.md), including this study's layer, [dentaquest-breach-2026.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/dentaquest-breach-2026.json)
- The [Team Star Wolf Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/)
- [All case studies](/case-studies/README.md)
