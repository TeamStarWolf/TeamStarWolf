# Slide plan: JPMorgan Chase 2014: Contact-Data Theft and the Wider Fraud Economy

- Study: case-studies/JPMORGAN_2014.md
- Cover title: JPMorgan Chase 2014 / Contact-Data Theft / and the Wider Fraud Economy
- Subtitle: How the 2014 JPMorgan Chase breach separates contact-data exposure from account compromise, and one bank's loss from a wider fraud campaign.
- Published: 15 November 2026
- Notes: Dark house style; evidence-bounded; keeps allegation, disclosure and adjudication on separate tracks.

## EXECUTIVE SUMMARY | Contact data earns protection even with no stolen credentials

- On 2 Oct 2014 the bank reported stolen contact data, with no evidence that credentials were taken.
- Contact data is not an account credential, but it is not valueless; harm can arrive later as deception.
- The bank's disclosures and the criminal record answer different questions and must not be merged.
- A January 2021 DOJ release named JPMorgan Chase and tied the anonymized record to a primary source.
Caption: Evidence grade: Confirmed disclosures, dated and category-bounded.
Notes: Executive assessment; absence-of-evidence is dated, not a guarantee. [1][6]

## KEY FACTS | Disclosures and the criminal record answer different questions

Stat: 76M | Households, bank estimate 2 Oct 2014
Stat: 7M | Small businesses, same filing
Stat: 80M+ | Customers named in 2021, DOJ
Stat: $19.2M | Tyurin forfeiture, 2021 sentence
- The 2015 indictment described more than 83 million records at an anonymized Victim-1.
- Household and business counts are stated categories, not a deduplicated count of people.
- The forfeiture belongs to Tyurin's sentencing, not money taken from bank accounts.
Caption: Evidence grade: Confirmed filings and DOJ records; units differ by source.
Notes: Keep units and dates attached to each figure. [1][3][6]

## PART 1 | The bank disclosed contact data, not account credentials

- The 2 October 2014 filing listed names, addresses, phone numbers, email and internal user information.
- It found no evidence that account numbers, passwords, user IDs, birth dates or SSNs were compromised.
- The firm reported no unusual customer fraud tied to the incident as of that date.
- No evidence of a kind of compromise is not proof that no harm can follow.
Caption: Evidence grade: Confirmed, as of the filing date.
Notes: Read each statement with its date and category intact. [1][2]

## PART 1 | Household and business counts are not a victim headcount

- A household can hold several people and a business several contacts; a sum is not a headcount.
- The filing gives no deduplication method or overlap analysis for its two categories.
- The 2021 release described more than 80 million customers, a differently scoped figure.
- A revised count should be dated and explained, not swapped in as a silent replacement.
Caption: Evidence grade: Confirmed figures, Inferred reconciliation limits.
Notes: Preserve the object counted, the period and the source date. [1][3][6]

## PART 1 | A disclosure date is not the first date of access

- A public disclosure date is not the first date of attacker access.
- Heartbleed appears at Victim-2 in the indictment, which does not establish the bank's entry point.
- An alleged multi-month window does not prove continuous access to every system.

| Track | What it records |
|---|---|
| Technical | Alleged June to August 2014 intrusion at Victim-1 [3] |
| Disclosure | 10 Sep and 2 Oct 2014 bank statements [2] |
| Criminal | 2015 charges, 2019 plea, 2021 sentence [4][5][6] |
Caption: Evidence grade: Allegation (indictment) versus dated disclosure.
Notes: Keep allegation, disclosure and adjudication on separate tracks. [2][3][4][5][6]

## PART 2 | Contact data is an input to fraud, not only withdrawals

- The Nov 2015 announcement alleged stolen contact data supported deceptive stock promotions.
- Campaign-wide allegations do not prove every record was used or every recipient acted.
- A customer directory can have value even when it carries no transaction authority.
- The bank may never see later deception inside its own transaction monitoring.
Caption: Evidence grade: Allegation, a charging announcement.
Notes: Keep the campaign scope distinct from the one bank. [4][5]

## PART 2 | The record shows criminal context, not state sponsorship

- The 2021 release reported a 144-month sentence and a $19,214,956 forfeiture for Tyurin.
- It named JPMorgan Chase among victims in a campaign across several sectors.
- 2015 charges against other defendants stay allegations; one plea does not resolve all cases.
- Nationality or location does not prove a government directed this incident.
Caption: Evidence grade: Adjudicated (plea, sentence) with stated limits.
Notes: Attribution evaluated at distinct evidence levels. [4][5][6]

## PART 2 | Campaign proceeds are not the bank's own losses

- Criminal proceeds are not bank losses, and forfeiture is not customer restitution.
- Campaign-wide proceeds include activity well beyond the bank breach.
- A cost ledger should separate investigation, support, remediation, litigation and fraud loss.
- The public record does not establish a complete lifetime cost for this breach.
Caption: Evidence grade: Confirmed figures, Inferred allocation limits.
Notes: Accurate categories beat a false grand total. [6]

## DEFENDER VIEW | Bulk export is its own authorization boundary

Left: Customer-data estate
- Map copies in service, analytics, marketing and legacy stores.
- Tie each dataset to an owner, purpose and expiry.
- Review service identities and scheduled jobs, not only employees.
Right: Bulk-access boundary
- Authorize export by population, fields, destination and duration.
- Separate routine lookup from unrestricted bulk export.
- Test with synthetic records; record pass, fail or incomplete.
Caption: Evidence grade: Demonstrated via synthetic-record testing.
Notes: Original defensive analysis, not bank internals. [1]

## DEFENDER VIEW | Keep service while shrinking exposure and downstream risk

- Availability and confidentiality are separate; no outage is not intact confidentiality.
- Plan scoped isolation and emergency authority before an incident forces the choice.
- Give customers an independent route to verify unexpected messages, no links required.
- Define recovery by verifiable claims, each with a concrete acceptance test.
Caption: Evidence grade: Demonstrated controls, original analysis.
Notes: Service can continue while confidentiality has failed. [2]

## MITRE MAPPINGS | No ATT&CK mapping without primary evidence

- The public sources do not support a bank-specific technical reconstruction.

| ATT&CK area | Mapping status |
|---|---|
| Initial access | Not mapped; no primary evidence [3] |
| Valid accounts | Not mapped; session risk is generic [5] |
| Exfiltration | Not mapped; bulk export is analytic [4] |
Caption: Evidence grade: Not mapped; the study declines without evidence.
Notes: Heartbleed at Victim-2 is not the bank's entry. [3][4][5]

## CROSS-CUTTING THEMES | Match each claim to what the source actually says

Left: Overstated risks
- Treating campaign proceeds as the bank's own losses.
- Reading forfeiture as money taken from bank accounts.
- Summing households and businesses into a victim headcount.
Right: Understated risks
- Dismissing contact data because no credentials were taken.
- Measuring harm only by unauthorized withdrawals.
- Ending the fraud process when the technical incident closes.
Caption: Evidence grade: an analytic synthesis across the sources.
Notes: Each claim matched to its evidence. [1][4][6]

## CLOSE | Protect relationships, test boundaries, keep meaning

- Protect customer relationships as well as credentials.
- Trace one high-volume contact dataset end to end.
- Test bulk-access boundaries with synthetic records.
- Rehearse how counts, absence-of-evidence and costs are reported.
Caption: Evidence grade: Recommendations, original analysis.
Notes: Make the limits visible while giving readers useful actions. [1][6]
