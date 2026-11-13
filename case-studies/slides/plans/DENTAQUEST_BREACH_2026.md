# Slide plan: The DentaQuest Health-Data Breach of May 2026: A Case Study

- Study: case-studies/DENTAQUEST_BREACH_2026.md
- Cover title: The DentaQuest Health-Data Breach / of May 2026 / A Case Study
- Subtitle: One employee, one MFA code and a file share of 15 million people's health plan data
- Published: 11 November 2026
- Notes: Slide plan for the deck of the study case-studies/DENTAQUEST_BREACH_2026.md, published 11 November 2026. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | One employee and one code were enough

- Dental and vision plan members, including Medicaid and Medicare enrollees, children and the deceased.
- Social engineering got one employee to hand over credentials and an MFA code.
- From 17 to 19 May 2026 the actor took data from a network file share; no malware was found.
- DentaQuest learned of it on 20 May, when a third party claimed to hold its data.
- HHS lists 15,000,000 people, the largest healthcare breach entry of 2026.
Caption: Evidence grade: Confirmed as DentaQuest's own statements to regulators and the HHS listing.
Notes: People in scope [1][4]. Entry and window [1]. Discovery [1]. HHS figure [8].

## KEY FACTS | A record breach with no CVE

Stat: 15M | People per HHS and Oregon
Stat: 3 days | Of access, 17 to 19 May
Stat: 234 GB | Claimed by ShinyHunters
Stat: 0 | Malware found by forensics
- Victim: DentaQuest, LLC, a Massachusetts health plan in the Sun Life U.S. Dental business.
- Claimed by ShinyHunters; DentaQuest's filings never name an actor.
- No CVE or KEV entry applies: this was an identity failure, not a software flaw.
Notes: Count [6][8]. Window [1][6]. Claim [14]. No malware [1]. Ownership [14]. No actor named [1]. No CVE, Inferred from [1][12].

## PART 1 | From file share to the HHS portal

| Date (2026) | Event |
|---|---|
| 17 to 19 May | One employee socially engineered; data taken from a file share |
| 20 May | A third party claims to hold the data; containment the same day |
| 29 May | DentaQuest learns the data was posted on the dark web |
| 30 May | Leak-site post last updated: about 234 GB (Reported) |
| 3 June | Have I Been Pwned adds 2.6 million email addresses (Reported) |
| 16 July | Notices to regulators; HHS lists 15,000,000 |
| 17 July | Individual notification by mail begins |
Caption: DentaQuest's consumer notice says the incident "ended by May 20"; counsel and Oregon give 19 May.
Notes: Window [1][4][6]. Discovery and containment [1]. Dark web [1]. Leak site [14]. HIBP [13]. Filings [1][4][6][8]. Mail [1][2]. End-date conflict [2] against [1][6].

## PART 2 | What counsel's letter says, and what it does not

Left: In the record
- One employee gave up credentials and an MFA code, against policy.
- Data left from a network file share; operating systems were not affected.
- No other compromised accounts, malware, privilege escalation or persistence.
Right: Not in the record
- Whether the lure came by phone or by email.
- What kind of MFA was in use.
- Which remote-access path or exfiltration channel the actor used.
Caption: The absences are why no lure sub-technique or exfiltration technique is bound.
Notes: Counsel's 16 July letter to the Rhode Island AG [1]; CrowdStrike Services findings as quoted there [1].

## PART 2 | Years of enrollment data on one share

- Names, birth dates, SSNs, Medicare and Medicaid IDs, plan numbers and dental and vision details.
- Much of the leak is ASC X12 enrollment files, some with Medicaid IDs (Reported).
- A folder of more than 1.7 million SSNs tied largely to Texas children (Reported).
- Files reportedly reach back to at least 2009.
- Separate letters for minors and deceased people confirm both were in scope.
Caption: Retention and share scope, not exploit code, set the size of this breach (Inferred).
Notes: Data types [1]. X12 files [13]. Children's SSNs and 2009 [16][17]. Letters [4].

## PART 3 | Attribution here is a claim

| Who | What they say |
|---|---|
| DentaQuest | A "Threat Actor"; no group named |
| ShinyHunters | Claimed about 234 GB; said talks failed |
| Indiana brief | Lists "Claimed Actor: ShinyHunters" |
| FBI PSA, 15 May | ShinyHunters in education; no DentaQuest |
| ATT&CK G1057 | Describes ShinyHunters; does not list DentaQuest |
Caption: G1057 and the Salesforce campaign C0059 are context only, not attribution.
Notes: Victim [1][2]. Claim [14][15]. Indiana [9]. FBI [10]. ATT&CK [23].

## DISCREPANCIES | Three numbers, one regulator count

| Figure | What it measures |
|---|---|
| 15,000,000 | People filed with HHS and the states |
| 2.6 million | Email addresses in the leaked data |
| 23.4 million | A dedupe of name and birth-date pairs |
| 4.5 million | Letters counted in three states' filings |
Caption: Cite the regulator figure and say what the others measure; the 15 million is a floor while the review ran.
Notes: Regulator figure [1][6][8]. Emails [13]. Dedupe [21]. Letters [18]. Floor, Inferred from [1].

## PART 4 | Response, regulators and the courts

- CrowdStrike Services and Kroll engaged; the FBI informed on 21 May.
- 24 months of Kroll identity monitoring and restoration offered.
- Filings with the Rhode Island, California, Oregon and South Carolina authorities.
- HHS OCR lists the breach as under investigation.
- Whitlow v. DentaQuest is reported as filed on 4 June (Reported).
Caption: Sun Life's Q2 release on 6 August discloses no incident or cost.
Notes: Response [1][2][5]. Filings [1][4][5][6][7]. HHS [8]. Lawsuit [22]. Sun Life [11].

## DEFENDER VIEW | The controls this record argues for

Left: Identity
- Treat code-based MFA as phishable.
- Phishing-resistant MFA for anyone who can reach member data.
- Identity checks on help-desk and reset paths.
Right: Data and detection
- Least-privilege share permissions and retention limits on X12 extracts.
- Alert on bulk file-share reads and large outbound transfers.
- Plan notification for minors and decedents before an incident.
Caption: A CVE queue would have shown nothing here (Inferred).
Notes: Entry vector [1]. Share and age [1][16]. Detection [1]. Notification [4]. The recommendations are Inferred.

## WHAT IS OVERSTATED | And what is understated

Left: Overstated
- "23 million affected": a dedupe, not a regulator figure.
- "ShinyHunters breached DentaQuest" stated as fact.
- Links to the Salesforce campaign C0059.
Right: Understated
- "2.6 million" counts email addresses, not people.
- The age of the data and the children's records.
- The victim's own documents disagree on the end date.
Notes: Dedupe [16][21]. Claim [1][9]. C0059 [1][23]. Emails [13][21]. Age and children [4][16][17]. End date [1][2][6].

## MITRE MAPPINGS | Five techniques, no group bound

| Id | Technique | Tie to DentaQuest |
|---|---|---|
| T1598 | Phishing for Information | One employee socially engineered |
| T1111 | Multi-Factor Authentication Interception | The MFA code handed over |
| T1078 | Valid Accounts | The employee's credentials used |
| T1039 | Data from Network Shared Drive | Data taken from a file share |
| T1657 | Financial Theft | The extortion claim |
Caption: ATT&CK v20.0. CAPEC-98 and CAPEC-560. ShinyHunters G1057 is context only.
Notes: Techniques [1][9][14][15] with [23]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## CROSS-CUTTING THEMES | Identity is the perimeter for data theft

- **A weak authentication step opened a healthcare intermediary,** as at Change Healthcare in 2024.
- **Extortion without encryption.** DentaQuest kept running while its data was published.
- **Counts are contested by design.** Actors inflate, analysts count emails, victims file a floor.
- **Old data is live risk.** Children's SSNs outlast any monitoring offer.
Notes: Change Healthcare comparison [1]. Extortion [1][14]. Counts [1][13][14][21]. Old data [16][17]. The themes are Inferred from the record.
