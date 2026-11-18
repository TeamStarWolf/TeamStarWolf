# Slide plan: Ledger 2020: Commerce Records, Phishing and Product Limits

- Study: case-studies/LEDGER_2020.md
- Cover title: Ledger 2020 / Commerce Records and Phishing / The Limits of Product Security
- Subtitle: A customer-data breach where commerce records, not wallet keys, exposed owners to phishing; dates, denominators and access paths stay distinct.
- Published: 18 November 2026
- Notes: The cover sets the frame: a customer-data and trust problem, not a wallet-key compromise.

## EXECUTIVE SUMMARY | Protecting a product is not protecting its customers

- Protecting a security product and protecting the people who buy it are related but different jobs.
- A device can keep its technical boundary while commerce records expose an owner to deception or threats.
- The study does not describe the leaked commerce database as a repository of wallet private keys.
- Estimates need dates and denominators: email addresses, records, customers and merchants are not one unit.
Caption: Evidence grade: Reported company notices; original analysis framing.
Notes: Executive-assessment framing; company facts rest on [1][2][5], with no stolen database reviewed.

## KEY FACTS | One breach, several numbers, different units

Stat: ~1M | Email addresses in July scope
Stat: 9,532 | Detailed records July logs identified
Stat: 272K | Detailed records in December release
Stat: 292K | Customer records in January update
- July 29, 2020 notice: June 25 API-key access, reported by a researcher July 14.
- December 21 account cited a public database of about 272,000 detailed customer records.
- Shopify reported fewer than 200 merchants in a separate support-access event.
- January 13, 2021 update: about 292,000 records, roughly 93 percent overlap, about 20,000 added.
Caption: Evidence grade: Reported company notices; units differ.
Notes: Figures from [1][2][3][5]; counts stay attributed estimates, not a fresh census.

## PART 1 | The July disclosure describes an access path, not an exploit

- Ledger's July 29 notice attributed unauthorized commerce-data access to an API key, which it disabled.
- Initial scope: about one million email addresses and about 9,500 contact or order records.
- Payment information and passwords were excluded; the device and Ledger Live boundary was reported unaffected.
- The notice supports an access-path description, not an invented endpoint or attacker command sequence.
Caption: Evidence grade: Reported, Ledger July 29, 2020 notice.
Notes: Access date, scope and exclusions from [1]; the wallet-boundary claim stays company-reported.

## PART 1 | Judge a credential by its authority, not the count

- Assess an API credential by which records it retrieves, which operations it allows and how it is logged.
- Counting credentials says little about how much customer data each one can expose.
- Keep the reporting date and the access date in separate fields.
- A patch can stop future use without identifying every earlier query.
Caption: Evidence grade: Inferred; original defensive analysis.
Notes: Credential-authority and date-separation guidance drawn from [1].

## PART 2 | December's revision: a minimum is not a maximum

- On December 21 Ledger's CEO cited a public database of about 272,000 detailed customer records.
- Earlier log review had identified 9,532 such records; the added detail was absent from analyzed logs.
- Demonstrated access can set a minimum known exposure, not proof other records were inaccessible.
- A missing log entry may mean a logging gap, an unreviewed source or genuinely absent activity.
Caption: Evidence grade: Reported company explanation, not independent validation.
Notes: Revised figure, log-limitation account and the minimum-versus-maximum point from [2].

## PART 2 | Shopify's support-access event was a separate path

- Shopify's September 22 announcement described two support staff improperly obtaining merchant records.
- It stated fewer than 200 merchants, denied a platform vulnerability and excluded full card numbers.
- Ledger's January 13 update said Shopify notified it on December 23 of exports in April and June.
- A discrepancy persists: Ledger's account said more than 200 merchants; Shopify said fewer than 200.
Caption: Evidence grade: Reported, contemporaneous company statements.
Notes: Shopify figures from [3][4]; the exports and the merchant-count discrepancy from [5].

## PART 2 | Heavy overlap forbids adding the datasets

- Ledger reported about 292,000 affected records, roughly 93 percent overlap and about 20,000 added.
- Adding every dataset size would double-count the many shared records.
- A rounded percentage does not establish an exact union of unique people.
- Converging paths do not prove one actor, one root cause or one intrusion causing the other.
Caption: Evidence grade: Reported figures; no independent reconciliation.
Notes: Overlap, additional-record figure and the single-actor caution from [5].

## PART 2 | Keep the event, discovery and publication clocks separate

The milestones differ; their order explains a changing picture without a new device compromise.

| Date | Milestone | Keep distinct |
|---|---|---|
| June 25, 2020 | API-key access, found later | Not the discovery date |
| July 14 to 29 | Report, first disclosure | Not the access date |
| Sep 22, 2020 | Shopify reports its event | A separate access path |
| Dec 21, 2020 | Public release, revised scope | Not a new intrusion |
| Jan 13, 2021 | Provider-related exposure | Not wallet-key compromise |
Caption: Evidence grade: Confirmed dated notices; non-claims kept explicit.
Notes: Sequence from [1-5]; store event, learned and publication dates in separate fields.

## PART 3 | Product security and customer security are distinct assets

- The threat model holds several assets: device, secrets, contact data, order record and support credibility.
- An order is not proof the buyer still owns the device, controls a wallet or lives at that address today.
- A customer list is not a reliable map of wealth, yet an attacker needs no balance to send a threat.
- State which component is not shown compromised, then separately which personal data escaped.
Caption: Evidence grade: Inferred; original threat-model analysis.
Notes: Asset distinctions and the dual boundary are original analysis, grounded in [1][2].

## PART 3 | Phishing makes leaked detail feel like authority

- Ledger reported phishing warnings in July and October, with open rates of 40 and 27 percent.
- It reported taking down more than 170 phishing sites by its December 21 account.
- These are reported outreach measures, not a count of who understood a warning or losses prevented.
- Personal detail is weak evidence of a sender's authority; verify through a known, independent channel.
Caption: Evidence grade: Reported company measures.
Notes: Warning dates, open rates and the 170-plus takedowns from [6].

## DEFENDER VIEW | Assist customers without collecting the secret

- Ledger's December 22 guidance warned against disclosing recovery words and acknowledged personal threats.
- It directed people in physical danger to local authorities; broad product-superiority claims are not adopted.
- A support ticket must never ask a customer to reveal a recovery phrase or upload a recovery sheet.
- Distinguish a suspicious message received from interaction, ordinary disclosure or a reported theft.
Caption: Evidence grade: Reported guidance, used as historical evidence only.
Notes: Recovery-secret warning and threat response from [7]; the support states are original analysis.

## DEFENDER VIEW | Scope credentials, watch support access, limit retention

Left: Access controls
- Map every system holding contact and order data, including integrations, exports and support tools.
- Give each credential an owner, a purpose and least-privilege scope; test revocation as a business operation.
Right: Support and retention
- Mask fields, limit bulk exports and require a recorded reason for exceptional support access.
- Segregation helps only if it changes who can access; deletion never retracts a copy already taken.
Caption: Evidence grade: Inferred; original recommendations, not Ledger's implementation.
Notes: Data-map, credential scope, support-console and retention points are original analysis, sections 9 to 11.

## CROSS-CUTTING THEMES | What this case overstates versus understates

Left: Overstated in the retelling
- "Ledger was hacked and funds stolen": the hardware-wallet keys were not breached.
- Adding dataset sizes into one victim total; heavy overlap double-counts.
- Treating internal deletion or segregation as erasing copies already acquired.
Right: Understated and worth keeping
- Commerce records enabled phishing, harassment and physical-threat campaigns.
- Separate access paths converged on much of the same customer data.
- Dates, denominators and units are not interchangeable.
Caption: Evidence grade: editorial corrections the case requires.
Notes: Contrasts drawn across [1][2][5][7]; keep affected versus compromised and claimed versus confirmed distinct.

## CLOSE | Name the data, the path, the date, the evidence, the gap

- A remediation plan should produce evidence someone other than its author can inspect.
- Measure the process: emails sent is not comprehension; deleted rows is not vanished copies.
- The durable lessons are scoped access, evidence quality, overlap-aware reporting and credible correction.
- Identify the data, access path, date and evidence, and state the remaining uncertainty plainly.
Caption: Evidence grade: a conclusion synthesis.
Notes: Acceptance-evidence and final-standard points from the study's closing sections, [1-8].
