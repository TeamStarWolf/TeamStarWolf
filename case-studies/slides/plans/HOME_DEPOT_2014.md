# Slide plan: Home Depot 2014: Payment Data, Vendor Access and the Cost of Unverified Boundaries

- Study: case-studies/HOME_DEPOT_2014.md
- Cover title: Home Depot 2014 / Vendor Access / Unverified Boundaries
- Subtitle: A legitimate vendor login opened the network, but the authority gained after entry, and how data and dollars were counted, is what the record shows.
- Published: 15 November 2026
- Notes: House-style TeamStarWolf case study; evidence-bounded, no invented exploit chain.

## EXECUTIVE SUMMARY | A vendor entry point is not the whole cause of a breach

The analytical question is not how the intruder entered but what authority they acquired afterward.

- A legitimate business relationship can become an entry point without being the entire cause.
- An account that cannot reach payment terminals still matters once later actions cross more boundaries.
- A breach needs three ledgers: technical, population (cards vs emails vs people), and financial.
- Different figures can all be accurate while answering different questions.
Caption: Evidence grade: a synthesis of company filings and regulator records.
Notes: Executive assessment and key takeaways. [1][2][3][4][5][6][7]

## KEY FACTS | Three headline numbers count three different things

Stat: ~56M | Payment cards at risk, reported Sep 2014
Stat: ~53M | Separate email addresses, Nov 2014
Stat: ~40M | Consumers nationwide, 2020 state figure
- US and Canadian stores affected; no evidence then of Mexican stores, online or debit PINs.
- The self-checkout exposure window was 10 April to 13 September 2014, per the 2020 NY AG.
- Email files held no passwords or card data; do not add emails to the card count.
Caption: Evidence grade: company-reported counts; the 2020 figure from a regulator.
Notes: [2] 56M cards; [3] 53M emails; [6] 40M consumers and the window; [1] initial scope.

## PART 1 | Disclosure dates and event dates are not the same

- 2 Sep 2014: the investigation begins after bank and law-enforcement information.
- 8 Sep 2014: the breach is confirmed; US and Canadian card use from April onward.
- 18 Sep 2014: malware eliminated, terminals removed, entry route closed; about 56M cards.
- The encryption project begun in January completed its US rollout on 13 Sep 2014.
- The 2020 NY AG set the window at 10 Apr to 13 Sep; a 2020 view, not day-one knowledge.
Caption: Evidence grade: company-reported containment, not independently verified.
Notes: [1] 2 and 8 Sep; [2] 18 Sep containment and encryption; [6] the 2020 window.

## PART 1 | Cards, addresses and consumers are different units

- Email files contained no passwords, card data or other sensitive personal information.
- The reviewed record gives no complete reconciliation across these units.
- Do not sum cards and emails into a single victim total.

| Population | Count | Source and unit |
|---|---|---|
| Payment cards, US and Canada | ~56M | Reported Sep 2014 [2] |
| Email addresses, separate | ~53M | Reported Nov 2014 [3] |
| Consumers nationwide | ~40M | 2020 state figure [6] |
Caption: Evidence grade: reported counts; the actual overlap is not established.
Notes: [2] cards; [3] email files; [6] consumers; no reconciliation in the record.

## PART 1 | One total hides four kinds of money

Stat: $63M | FY2014 pretax gross expense
Stat: $33M | FY2014 net after insurance
Stat: $298M | Cumulative gross by FY2016
Stat: $198M | Cumulative net by FY2016
- FY2014: $63M gross, $30M expected insurance, $33M net; period figures, not final.
- FY2016: $298M gross, $100M expected insurance, $198M net; $80M received, $20M receivable.
- The cumulative amount is neither all-cash nor a demonstrated lifetime total.
- Keep the settlement as a separate dated line; do not add or subtract naively.
Caption: Evidence grade: Confirmed securities filings, for specified periods.
Notes: [4] FY2014 63/30/33; [5] FY2016 298/100/198, 80 received, 20 receivable.

## PART 2 | Stolen vendor credentials did not reach the terminals

The record describes a sequence of authority transitions, not a single step.

- Attackers used a third-party vendor username and password to enter the perimeter.
- Those credentials did not themselves provide access to point-of-sale devices.
- Rights were elevated, the environment traversed, and custom malware placed on self-checkout.
- The announcement did not identify the specific escalation mechanism.
- Each transition from external identity to payment system deserves its own control.
Caption: Evidence grade: company-reported; the escalation method was not disclosed.
Notes: [3] vendor credentials, elevation, custom malware on US and Canadian self-checkout.

## PART 2 | Vendor access is a relationship, not a one-time check

Left: What a questionnaire records
- The supplier's stated controls.
- The commercial intent of a contract.
- A point-in-time attestation.
Right: What infrastructure actually permits
- Named users, service and emergency accounts.
- Active sessions, cached credentials, remote agents.
- Offboarding tested on closed engagements.
Caption: Original defensive analysis for comparable retailers.
Notes: [3] vendor-credential origin; the vendor-lifecycle controls are original analysis.

## PART 2 | Management paths can change payment behavior

- A payment terminal sits inside software distribution, remote support, identity and logging.
- Keep two diagrams: the payment-data path and the administrative path.
- They meet wherever administrative authority can affect payment handling.
- Segmentation tests should permit a single repair, not reach every store.
- A boundary should survive a plausible compromise of an adjacent system.
Caption: Original defensive analysis; not the retailer's historical design.
Notes: [3] the described progression; the boundary and integrity analysis is original.

## PART 2 | Encryption and EMV solve two different problems

- Payment encryption reduces readable transaction data along a protected path.
- EMV uses a transaction-specific cryptogram to curb counterfeit reuse.
- Encryption alone does not remove cardholder data from PCI DSS scope, per the current FAQ.
- A product description is not a formal point-to-point encryption validation.
- Report installed equipment, enabled functionality and verified protection separately.
Caption: Evidence grade: contemporary context, not 2014 compliance proof.
Notes: [8] the PCI SSC FAQ scope; [9] the EMVCo cryptogram; [2] the company encryption rollout.

## PART 2 | A 2020 settlement is an agreement, not a verdict

Stat: $17.5M | 2020 multistate settlement
Stat: 46+DC | States plus the District of Columbia
- The NY AG announced the multistate settlement in November 2020.
- The NJ executed assurance, effective 21 December 2020, sets the precise obligations.
- Obligations span governance, account review, logging, file integrity, vendor access, testing.
- A nonadmission clause applies; the agreement is not a regulatory endorsement.
- Dividing the payment by the breach population does not yield an individual entitlement.
Caption: Evidence grade: a Confirmed settlement and executed assurance.
Notes: [6] the NY AG announcement; [7] the NJ executed assurance and legal qualifications.

## DEFENDER VIEW | Measure response and verified boundaries, not volume

- Detection should start from meaningful payment-environment changes, not alert volume.
- Terminal software needs an approved baseline and a named distribution owner.
- Recovery claims should list each containment action and its supporting evidence.
- Closure should replay authorization tests: can a revoked identity still connect?
- Scorecards need honest denominators, including emergency and non-human access.
Caption: Original defensive analysis; Demonstrated through acceptance tests.
Notes: Detection, recovery and scorecard sections are original; [3] custom malware.

## CROSS-CUTTING THEMES | What gets overstated and what gets understated

Left: Overstated
- A single combined victim or cost headline.
- Containment read as proof every capability was removed.
- A chip reader treated as full data confidentiality.
Right: Understated
- The distinct authority gained after entry.
- Management paths adjacent to payment devices.
- Residual uncertainty and unresolved legal claims.
Caption: Reading discipline: faithful to dated facts and their limits.
Notes: [2][3] population limits; [4][5] money ledgers; [8][9] encryption versus EMV.

## CLOSE | Verify every transition of authority

- Do not let a supplier, privilege, management path or payment process inherit trust.
- Keep cards, addresses and consumers as distinct meanings.
- Keep gross expense, insurance recovery and regulatory payment as distinct meanings.
- Good analysis is useful without pretending to hold an unpublished forensic report.
Caption: Scope: a historical synthesis, not a current-state assessment.
Notes: Enduring lessons and the research limitations. [1]-[7]
