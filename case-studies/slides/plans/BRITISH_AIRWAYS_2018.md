# Slide plan: British Airways 2018: The Payment Page Was Not the Breach

- Study: case-studies/BRITISH_AIRWAYS_2018.md
- Cover title: British Airways 2018 / Magecart skimming / Scope and penalty
- Subtitle: A browser-visible card skimmer was the final expression of a longer access path; scope, exposure and penalty each need their own bounded account.
- Published: 18 November 2026
- Notes: The cover sets the frame: a visible symptom at the end of a longer access path, not a single headline.

## EXECUTIVE SUMMARY | The payment page was the symptom, not the breach

- A customer can see the right brand and get a legitimate confirmation while a compromised component handles data in an unauthorized way.
- Successful business functionality is not enough to establish the security of a transaction.
- The control model spans remote access, privilege, deployment, runtime observation and data minimization.
- Passing a vulnerability scan does not prove payment-page integrity.
Caption: Evidence grade: Inferred analysis built on Confirmed records.
Notes: Executive-assessment framing; the record rests on sources [1] through [5].

## KEY FACTS | Different units forbid one headline number

Stat: 429,612 | ICO estimate of individuals with access
Stat: 244,000 | Revised affected payment-card details
Stat: GBP 20M | Final penalty the ICO imposed
Stat: 183.39 | GBP million originally proposed
- The ICO notice describes an incident spanning June 22 to September 5, 2018.
- IAG's booking exposure window ran from late August 21 through September 5, 2018.
- Articles 5(1)(f) and 32 GDPR were found infringed, and BA did not admit liability.
Caption: Evidence grade: Confirmed dates and figures, kept in separate units.
Notes: Individual estimate and penalties from [1]; card and booking figures from [2] and [3].

## PART 1 | The documented core sits in the ICO penalty notice

- The ICO's October 16, 2020 notice is the primary regulatory record for this incident.
- Compromised third-party remote-access credentials led to movement beyond intended access.
- Exposed privileged credentials and modified website JavaScript followed; some steps stayed redacted.
- Unnecessary payment-data logging is addressed separately from the skimming itself.
Caption: Evidence grade: Confirmed (ICO notice); some mechanisms redacted.
Notes: Mechanism, infringements and the logging finding from [1].

## PART 1 | Four clocks explain the apparently conflicting dates

The clocks overlap but are not interchangeable; none is automatically a contradiction.

| Clock | What it measures | Example from the record |
|---|---|---|
| Unauthorized access | Foothold or authority held | June 22 to September 5, 2018 |
| Collection | Transactions or records exposed | August 21 to September 5, 2018 |
| Disclosure | Public notification | September 6, 2018 |
| Adjudication | Regulator's final finding | October 16, 2020 |
Caption: Evidence grade: Confirmed dates; the four-clock split is original framing.
Notes: Intrusion period from [1]; the booking window and disclosure date from [2].

## PART 1 | Scope accounting: cards, people, records, and notices

- Payment-card details, individual people, account records and notification recipients are different units.
- IAG revised the originally identified card group from 380,000 to 244,000 affected card details.
- It separately notified holders of 77,000 and 108,000 cards as a precaution for reward bookings.
- Precautionary notification is not confirmation that data was removed or misused.
Caption: Evidence grade: Reported corporate figures; records at risk kept apart from misuse.
Notes: Revised card population and precautionary groups from [3]; the no-passport-data statement from [2].

## PART 1 | RiskIQ attributes the skimming to Magecart

- RiskIQ's September 11 research announcement attributed the web skimming to Magecart.
- It described modified payment scripts that preserved normal functionality while sending data elsewhere.
- Its Ticketmaster comparison separated direct site compromise from third-party-script distribution.
- This is a vendor assessment, not a criminal conviction or a claim of one operator across all cases.
Caption: Evidence grade: Reported vendor attribution, not an adjudicated finding.
Notes: Attribution, script behavior and the comparison from [4]; its early figure is not adopted as the count.

## PART 2 | A proposal is not a final fine

Stat: 183.39 | GBP million originally proposed
Stat: GBP 20M | Final penalty imposed
- The ICO weighed BA's representations, mitigation and pandemic circumstances.
- The gap should not be presented as a simple automatic discount.
- Pogust Goodhead reports its BA claim resolved in July 2021 on confidential terms.
- A regulatory penalty and a private settlement are different outcomes, not one combined total.
Caption: Evidence grade: Confirmed penalty; Reported settlement.
Notes: Proposed and final penalty from [1]; the confidential settlement from [5].

## PART 2 | A five-boundary model organizes the review

This model is original synthesis, not an official taxonomy used by the regulator.

| Boundary | Control question |
|---|---|
| Remote entry | Which identity, purpose and reachable resources? |
| Internal authority | Can one session reach an unrelated admin environment? |
| Privileged material | Who can read secrets stored in ordinary files? |
| Publication | Who can change a customer-facing component? |
| Client-side execution | What code runs, and what data is retained? |
Caption: Evidence grade: Inferred synthesis, not an official taxonomy.
Notes: Boundaries abstracted from the mechanism the notice records [1].

## PART 2 | Logs can become an unintended payment database

- Diagnostic systems can accumulate fragments of the same payment transactions.
- A field copied into a log can bypass retention, access review and classification.
- Test error paths, since failures may log more detail than successful transactions.
- Retention helps only when it reaches copied archives and troubleshooting exports.
Caption: Evidence grade: Inferred guidance; the notice cited unnecessary logging.
Notes: The unnecessary payment-data logging finding anchors this from [1].

## PART 2 | Client-side integrity requires more than one control

- A defensible program combines inventory, authorization, integrity checks, runtime observation and response.
- An approved component can later change behavior, and a checksum covers one artifact only.
- A restrictive policy can be weakened by an exception, and an alert needs someone to act.
- Build an independently reviewable path from approved behavior to what the customer receives.
Caption: Evidence grade: Inferred architectural recommendation.
Notes: Combined-control argument and the review path are original analysis tied to [1] and [4].

## DEFENDER VIEW | Normal bookings do not prove normal data handling

- A transaction can complete while an additional unauthorized action occurs.
- Define approved behavior first, so deviations can be classified rather than guessed.
- Ask what destinations receive data and which scripts can touch sensitive fields.
- Use synthetic transactions; a successful-checkout screenshot shows appearance, not integrity.
Caption: Evidence grade: Inferred test discipline drawn from the study.
Notes: Functional-versus-confidentiality distinction and synthetic-data rule from [4].

## DEFENDER VIEW | Trace each conclusion to an observation and source

The matrix prevents category errors; adapt the rows, but keep the evidence specific.

| Question | Useful evidence | Invalid shortcut |
|---|---|---|
| Which population? | Unit, dataset, interval, confidence | A single headline number |
| Change in effect? | Post-change runtime evidence | A removed file alone |
| Confirmed or at risk? | Exposure versus verified misuse | A notice read as proof |
| Exception controlled? | Owner, expiry, compensating test | An indefinite waiver |
Caption: Evidence grade: an original review tool.
Notes: Condensed from the scope ledger and containment guidance in [1] and [3].

## CROSS-CUTTING THEMES | What the record overstates versus understates

Left: Easy to overstate
- Reading the proposed 183.39M figure as the fine actually imposed.
- Multiplying affected people by a settlement to invent a per-person award.
- Treating a precautionary notice as confirmed data removal.
Right: Easy to understate
- The intrusion period was broader than the booking exposure window.
- Logs and exports form a second data estate beyond the live page.
- Removing an altered file leaves the authority that allowed it.
Caption: Evidence grade: editorial corrections the case requires.
Notes: Penalty and settlement limits from [1] and [5]; scope and logging points from [2] and [3].

## CLOSE | A bounded account beats a single headline number

- The breach is the paths linking remote access, internal authority, publication, live behavior and retained data.
- Keep early and later figures, possible and confirmed exposure, and proposed and final penalty distinct.
- A private settlement and a public penalty are separate outcomes, neither a measure of total loss.
- Deliver a bounded, versioned account over one reassuring headline number.
Caption: Evidence grade: case-specific conclusions, outcome claims bounded.
Notes: Conclusion synthesis across the study, resting on [1] through [5].
