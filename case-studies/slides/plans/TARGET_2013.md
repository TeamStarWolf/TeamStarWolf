# Slide plan: Target, 2013: Vendor Access, Payment Boundaries and the Last Register

- Study: case-studies/TARGET_2013.md
- Cover title: Target, 2013 / Vendor Access, Payment Boundaries / and the Last Register
- Subtitle: The breach is a chain of trust and coverage questions, not a single ignored alert.
- Published: 15 November 2026
- Notes: This is an evidence-bounded account from dated retailer disclosures, congressional materials and a later state investigation; the recommendations and tabletop are original defensive analysis, not a current audit of Target.

## EXECUTIVE SUMMARY | Target is a chain of trust and coverage questions

- **Connected system:** it links third-party access, internal boundaries, payment systems, detection decisions and remediation coverage.
- **Not a one-line story:** "a vendor was compromised" or "a product alerted" raises the real questions, it does not answer them.
- **Units matter:** card accounts and people with exposed contact data are different populations with possible overlap.
- **Coverage lesson:** an enterprise-wide action is complete only when its reach and exceptions are known.
Caption: Evidence grade: dated disclosures and one state investigation; original analysis is labeled.
Notes: The four threads here are the spine of the deck. The remediation chronology, including registers not connected during the initial cleanup, is a general operational lesson. [1][2][3]

## KEY FACTS | Four figures that must keep their dates and units

Stat: 40M | Card accounts, up to approx, FY2014
Stat: 70M | Individuals with contact data exposed
Stat: USD252M | Cumulative expense to Jan 31 2015
Stat: USD18.5M | Later multistate settlement, 2017
- Figures come from different sources and dates: a 2017 state announcement cited 41M+ accounts and 60M+ customers.
- Do not add 40M and 70M: that yields neither a unique-person count nor a measure of confirmed fraud.
- Net cumulative expense was USD162M after USD90M of expected insurance recoveries.
Caption: Evidence grade: Confirmed source figures, each tied to its own report.
Notes: Each stat carries its source date and population. The settlement is a distinct later legal outcome, not the lifetime cost. [4][5][7]

## PART 1 | January expanded the scope, it was not a new breach

- The January 10, 2014 update identified stolen guest information separate from the earlier payment-card data.
- It described names, addresses, phone or email for up to 70 million individuals, much of it partial.
- Target stated this was newly identified scope within the same incident, not a second intrusion.
- Outreach was said not to request personal information; historical offers are not current advice.
Caption: Evidence grade: Confirmed dated company statement.
Notes: Resist retelling this as a January attack or as 70 million stolen cards. Different categories create different risks and different communication duties. [1]

## PART 2 | The detection and cleanup account changed over time

- Feb 2014 CFO testimony: DOJ notified Target Dec 12, malware confirmed Dec 15, removed from virtually all US registers that day.
- That early account also cited disconnected registers addressed Dec 18 and fewer than 150 additional guest accounts.
- The fiscal 2013 report gave a more specific residual: 56 guests during Dec 16-17 before one disconnected register was disabled.
- The principal card window was described as November 27 to December 15, later summarized through December 17.
Caption: Evidence grade: Confirmed; preliminary testimony and later filings both preserved.
Notes: The distinction is between broad cleanup, discovery of exceptions and the revised exposure window. "Most systems remediated" does not establish every device was clean. [2][3][4]

## PART 3 | Card accounts and exposed people are different units

- Fiscal 2014 report: up to approx 40M credit and debit card accounts, and contact information for up to 70M individuals.
- 2017 Connecticut announcement: more than 41M payment-card accounts and contact data for more than 60M customers.
- These are source-specific figures with their own dates and units, not interchangeable exact counts.
- A scope chart should list population, data type, source date, confidence and limitations, leaving overlap blank if unproven.
Caption: Evidence grade: Confirmed source figures; a deduplicated total is unestablished.
Notes: Do not take the largest number from each source and add them. A transparent missing total beats a precise number built from incompatible measurements. [4][5]

## PART 4 | Vendor access carried reach beyond the vendor's task

- The 2017 state announcement said attackers used credentials stolen from a third-party vendor to reach a Target gateway around Nov 12, 2013.
- It described further access, malware installation and capture of customer and payment information.
- The USD18.5M multistate settlement required segmentation, governance and controls for certain accounts.
- A legitimate business relationship should not imply authority over unrelated sensitive systems.
Caption: Evidence grade: Reported; the states' investigation account, not a full forensic reconstruction.
Notes: The study does not establish how the credentials were first stolen, nor claim a building-control device directly compromised every terminal. Those steps need evidence. [5]

## PART 5 | The Senate report synthesizes, it does not adjudicate

- The March 2014 Senate Commerce staff report says it relies on media reports and published expert analysis.
- It applies a kill-chain framework and describes apparent missed opportunities in access, isolation and warnings.
- Official hosting does not convert every media-derived detail into an independently verified forensic finding.
- The deck does not assert that one person saw a decisive warning and deliberately ignored it.
Caption: Evidence grade: Reported; a public-record synthesis, not a forensic verdict.
Notes: The surviving lesson is that detection is an operational process, not an installed tool: generate, deliver, triage, decide, verify. Each handoff can fail while another works. [6]

## PART 6 | Cost and compliance each need their own scope

- Fiscal 2014 report: cumulative expenses USD252M as of Jan 31 2015, offset by USD90M expected insurance, netting USD162M.
- The fiscal 2014 earnings release reports USD191M gross and USD46M receivable for that year, included in the cumulative figure.
- Expense recognition and expected recovery are not the same as cash paid and cash received.
- The filing notes a dispute between an assessor's findings and the networks' forensic investigator about compliance at the breach date.
Caption: Evidence grade: Confirmed filings; figures overlap, so do not sum them.
Notes: A breach does not by itself prove which control failed or that every assessment conclusion was wrong. Compliance is a point-in-time review against defined criteria. [4][7]

## DEFENDER VIEW | Segmentation is a property to test, not a diagram

Left: Vendor access
- Shape access to the business task, not the vendor's reputation.
- Give each relationship an internal owner who approves changes.
- Record an expiry or review trigger; a dormant credential is still attack surface.
Right: Segmentation and payment data
- A diagram is not evidence; test routes, identities, services and management authority.
- Define what the boundary should prevent, then test that objective.
- Follow payment data through capture, processing, logging and support, not just storage.
Caption: Evidence grade: a Demonstrated method using synthetic data and approved identities.
Notes: Verify boundaries after deployment and after system updates, since they drift when new integrations or emergency routes appear. Use benign checks with synthetic information, never real card data. [7]

## DEFENDER VIEW | The last disconnected device decides coverage

- Centrally managed remediation assumes devices are online; an offline device can return later with an old or malicious state.
- Keep a reconciled inventory: expected devices, last-seen status, ownership and exceptions.
- A missing completion acknowledgment should trigger an exception workflow, not silently count as success.
- Define return-to-service checks so a returning terminal cannot resume a sensitive function unverified.
Caption: Evidence grade: Demonstrated; test with a deliberately disconnected lab device.
Notes: This generalizes the revised register counts: absence during a cleanup must not exempt a device from the cleanup. An alert must also end in an accountable, verified decision. [2][3]

## MITRE MAPPINGS | No technique chain is asserted as settled fact

| Reported step | Evidence status |
|---|---|
| Vendor credential theft method | Not established [5] |
| Gateway access via vendor creds | States' investigation [5] |
| POS malware on US registers | Confirmed by Target [2] |
| Card and contact data captured | Described in filings [4][5] |
Caption: No formal ATT&CK technique IDs are claimed; boundaries are kept explicit.
Notes: The study stops short of a mapped technique chain because the public record mixes confirmed filings, a states' summary and a media-based synthesis. State what is reported versus confirmed rather than filling gaps. [2][4][5][6]

## CROSS-CUTTING THEMES | What gets overstated, and what gets understated

Left: Overstated
- A single ignored alert explains the breach.
- Adding 40M and 70M yields a unique-victim total.
- A prior compliance pass proves the environment was safe.
Right: Understated
- Trusted vendor access can reach unrelated sensitive systems.
- Remediation was incomplete until disconnected devices were covered.
- Population figures carry dates and units, not one deduplicated count.
Caption: Evidence grade: mixed; each claim is weighted to its strongest source.
Notes: Use this slide to correct the familiar retellings. The single-cause narrative is the overstated one; the coverage and boundary lessons are the understated ones that transfer. [2][4][5][6]

## CLOSE | Replace reassurance with verifiable claims

- Target 2013 is a chain of trust and coverage questions: external reach, payment isolation, warning handling, remediation completeness.
- A ninety-day programme can test one vendor-supported workflow end to end: boundaries, alerts, a disconnected device, an expired account.
- Report outcomes with their scope: a selected workflow can improve without the enterprise becoming breach-proof.
- Strong research preserves dates, units and source limits; strong defense tests boundaries with safe synthetic evidence.
Caption: Evidence grade: original analysis, scoped and labeled as such.
Notes: Leave the audience with the method. The fictional tabletop (vendor anomaly, suspected malware, unchecked-in devices, a revised category) rehearses these decisions in an isolated environment. [1][2][5]
