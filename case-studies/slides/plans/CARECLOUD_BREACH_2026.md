# Slide plan: The CareCloud Medical-Records Breach of March 2026: A Case Study

- Study: case-studies/CARECLOUD_BREACH_2026.md
- Cover title: The CareCloud Medical-Records Breach / of March 2026 / A Case Study
- Subtitle: One cloud account, six days and the records of 3.7 million patients
- Published: 11 November 2026
- Notes: Slide plan for the deck of the study case-studies/CARECLOUD_BREACH_2026.md, published 11 November 2026. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | The patients never chose this vendor

- CareCloud runs EHR and clinical documentation services for healthcare organizations.
- From 10 to 16 March 2026 a third party had access to one of its AWS environments.
- Forensics found one cloud account accessed and PII and PHI exfiltrated.
- HHS lists CareCloud as a business associate: 3,756,469 individuals.
- No filing names an actor, malware, CVE or entry method.
Caption: Evidence grade: Confirmed as CareCloud's SEC filings, its consumer notice and the HHS listing.
Notes: Services [8]. Window [6][8]. Forensic finding [3][4]. HHS [9]. Absences [1][2][3][4][8].

## KEY FACTS | A large health breach with no CVE

Stat: 3.76M | Individuals per HHS
Stat: 6 days | Of access, 10 to 16 March
Stat: 8 hours | Of partial EHR outage
Stat: 1 of 6 | EHR environments touched
- Victim: CareCloud, Inc. of Somerset, New Jersey (Nasdaq CCLD), its CareCloud Health division.
- Attribution: "an unauthorized third party"; no group claim as of 19 August (Reported).
- No CVE or KEV entry appears in the record; that none applies is Inferred.
Notes: HHS [9]. Window [6][8]. Outage and environments [1]. Attribution [1][2][3][4]; no claim [10]. CVE and KEV [11].

## PART 1 | From disruption to the HHS portal

| Date (2026) | Event |
|---|---|
| 10 to 16 March | Access to one AWS environment; 8-hour outage on 16 March |
| 24 March | Incident judged material |
| 27 March | Form 8-K Item 1.05 filed |
| 7 May | Q1 10-Q: data exfiltrated; two class actions |
| 24 July | HHS report: 3,756,469 individuals |
| 25 July | California AG listing; notices begin |
| 6 August | Q2 10-Q: one cloud account; PII and PHI taken |
| 5 November | Q3 10-Q: no regulator claim; settlement talks |
Caption: No Item 1.05 8-K/A was filed through 5 November; the updates came in the 10-Qs.
Notes: Window and outage [1][6][8]. Materiality and 8-K [1]. Q1 [2]. HHS [9]. California [6][7][10]. Q2 [3]. Q3 [4]. EDGAR [5].

## PART 2 | Four documents, four depths

Left: In the record
- 8-K: a same-day "temporary network disruption".
- Q1 10-Q: access began about a week earlier.
- Notice: AWS environment, 10 to 16 March.
- Q2 and Q3: one cloud account; PII and PHI taken.
Right: Not in the record
- How the cloud account was obtained.
- What credential type was used.
- How the data left, or what alerted defenders.
Caption: The absences are why no exploit, exfiltration or impact technique is bound.
Notes: 8-K [1]. Q1 [2]. Notice [8]. Q2 and Q3 [3][4]. Absences [1][2][3][4][8].

## PART 2 | What the notice says was taken

- Full name plus one or more other elements for each person.
- The sample letter leaves the other elements as a placeholder.
- The California copy's file name references SSN (SSN involvement Inferred).
- Q2 and Q3 10-Qs: PII and PHI of a substantial number of individuals.
- The notice says CareCloud knows of no identity fraud from the incident.
Caption: The data elements were determined on 24 June, three months after containment.
Notes: Elements [8]. File name [8]. Forensic finding [3][4]. Fraud statement [8]. Date [8].

## DISCREPANCIES | Where the documents differ

| Question | Early record | Later record |
|---|---|---|
| What happened | "Temporary network disruption" | Six days of access |
| Exfiltration | Being assessed | PII and PHI taken |
| Scope | One of six EHR environments | One cloud account |
| Count | No SEC filing gives one | HHS: 3,756,469 |
Caption: Cite the HHS figure and say where it comes from; the SEC filings never state a number.
Notes: Framing [1] against [2][3][8]. Exfiltration [1][3]. Scope [1][3]. Count [3][4][9].

## PART 3 | Who and why: an unnamed third party

| Question | What the record says |
|---|---|
| Actor | "An unauthorized third party" |
| Group claim | None as of 19 August (Reported) |
| Motive | Not stated; "claimed" fits extortion (Inferred) |
| Ransom or leak | None in the filings or notice |
| Law enforcement | Told; agency not named |
Caption: Press naming of any group after 19 August was not checked.
Notes: Actor [1][2][3][4]. Claim [10]. Motive [3][8]. Ransom [3][4][8]. Law enforcement [1].

## PART 4 | Response, regulators and the courts

- 12 or 24 months of IDX monitoring and a $1,000,000 reimbursement policy offered.
- Insurance covers costs above a $100,000 retention, which was accrued.
- HHS and California list the breach; no regulator has asserted a claim.
- Class actions consolidated in Florida; a California action removed to federal court.
- Settlement discussions are ongoing, per the Q3 10-Q.
Caption: Dockets were not opened; the court record is the company's account.
Notes: Monitoring [8]. Insurance [3][4]. Regulators [4][6][7][9]. Courts [2][3][4].

## DEFENDER VIEW | The controls this record argues for

Left: Identity
- Treat cloud accounts that reach patient data as crown jewels.
- Phishing-resistant MFA and short-lived credentials.
- No standing access keys.
Right: Detection and design
- Alert on bulk database reads and large outbound transfers.
- Keep each EHR tenant in its own cloud account.
- Track the vendor's 10-Qs and HHS entry, not only the 8-K.
Caption: A CVE queue would have shown nothing here (Inferred).
Notes: Entry point [3]. Detection [1][8]. Tenant split [1]. Disclosure stages [1][2][3]. The recommendations are Inferred.

## WHAT IS OVERSTATED | And what is understated

Left: Overstated
- Calling it a ransomware attack: no filing mentions ransomware or encryption.
- Treating 3,756,469 as an SEC-disclosed number.
Right: Understated
- The 8-K's "temporary network disruption" framing.
- Six days of access and confirmed exfiltration.
- The SEC incident filing still carries the early framing.
Notes: Ransomware [1][8][10]. Count [3][4][9]. Framing [1][3][9]. No amendment [5].

## MITRE MAPPINGS | Two techniques, no group bound

| Id | Technique | Tie to CareCloud |
|---|---|---|
| T1078.004 | Valid Accounts: Cloud Accounts | One cloud account used |
| T1213.006 | Data from Information Repositories: Databases | Data claimed taken from databases |
Caption: ATT&CK v20.0. CAPEC-560 and CAPEC-150. No CWE: no CVE applies.
Notes: Techniques [3][4][8] with [13]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## CROSS-CUTTING THEMES | Vendors carry the counts

- **Business associates fill the largest HHS entries,** with Aesto and TriZetto in 2026.
- **Change Healthcare in 2024 is the precedent** for a vendor breach reaching patients.
- **Theft without encryption,** as in the Cl0p file-transfer breaches.
- **Disclosure moves in stages:** only the 8-K, 10-Qs, HHS and the notice together tell it.
Notes: Watchlist [14]. Change Healthcare [15]. Theft without encryption [3]. Stages [1] to [9]. The themes are Inferred from the record.
