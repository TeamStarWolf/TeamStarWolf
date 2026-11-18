# Slide plan: TalkTalk 2015: The Acquired Attack Surface

- Study: case-studies/TALKTALK_2015.md
- Cover title: TalkTalk, 2015 / The Acquired Attack Surface / Owning is not governing
- Subtitle: Owning an online service is not governing its routes to customer data; incident numbers measure different things and need dates and definitions.
- Published: 18 November 2026
- Notes: The cover sets the frame: inherited reach to customer data, and numbers that must stay defined.

## EXECUTIVE SUMMARY | Owning a service is not governing its data routes

- The subject is the gap between owning an online service and governing its routes to customer data.
- Incident numbers measure different things; combining them into one dramatic total hides the real choices.
- The recommendation is an acquisition-to-retirement control process for inherited services.
- These are proposals for comparable organizations, not claims that the process existed at TalkTalk.
Caption: Evidence grade: Confirmed findings; the recommendations are analysis.
Notes: Executive-assessment framing from [1]; the control-process proposal is original analysis, not a retrospective claim.

## KEY FACTS | What the regulator established, with dates

Stat: 156,959 | Customers in ICO-established scope
Stat: 15,656 | Of those, bank account and sort-code
Stat: 3.5 yrs | Database fix available before attack
Stat: 400,000 | ICO penalty, GBP, Data Protection Act
- The ICO found unsecured pages, inadequate monitoring and outdated database software.
- The bug bypassed database access restrictions; a fix had been available for over three years.
- Attack dates were 15 to 21 October 2015, through three pages inherited from Tiscali in 2009.
Caption: Evidence grade: Confirmed regulatory findings.
Notes: Scope, bank-detail subset and the available fix from [1]; the penalty is a regulator action, distinct from company statements.

## PART 1 | Four clocks the incident team must keep separate

Dates are institutional milestones, not proof of uninterrupted attacker residence across them.

| Clock | Dated milestone |
|---|---|
| Earlier injection activity | 17 July and 2 to 3 September 2015 |
| Exposure window | 15 to 21 October 2015 |
| Detection and site removal | 21 October 2015 |
| External notification | ICO 22 Oct; customers from 22 Oct |
| Public inquiry opened | 3 November 2015 |
Caption: Evidence grade: Confirmed dates; not proof of continuous access.
Notes: Attack and detection chronology from [1]; notification, ransom discussion and inquiry milestones from [2].

## PART 1 | Acquisition does not end at legal completion

- Infrastructure can outlive the business process that first justified it; an old portal may still resolve and reach records.
- Labels such as legacy, dormant and transitional are not technical access controls.
- At close, record each service's purpose, external address, business owner, operator and information classes.
- Decide each inherited service: retain with verified controls, isolate, or retire with evidence.
Caption: Evidence grade: Inferred, original governance proposal.
Notes: The acquisition connection draws on [1]; the intake and three-outcome design is original analysis, not a claim about the integration contract.

## PART 1 | SQL injection is a trust-boundary failure

- OWASP frames SQL injection as untrusted data becoming part of a database command's syntax.
- The preferred fix separates command structure from bound data values; manual escaping is discouraged.
- The question is not whether a form rejects punctuation, but whether every path keeps data and instructions apart.
- Parameter binding does not decide whether a caller is authorized to receive a given account's data.
Caption: Evidence grade: Demonstrated defensive pattern (OWASP), not TalkTalk source code.
Notes: Injection mechanism and binding limits from [8]; verification should use synthetic records in an authorized test environment.

## PART 2 | Patching and application repair are different work

- A database update and a query-construction fix address different sources of risk.
- Do not close an application defect because the platform is current, nor close a platform defect because a route was rewritten.
- Each corrective item needs a failed control, affected population, remedy, owner and required evidence.
- Temporary access restrictions need an expiry and a clear statement of what stays reachable.
Caption: Evidence grade: Inferred, original work breakdown.
Notes: The control boundaries build on [1]; the register design is an original defensive proposal, not an assertion about 2015 tickets.

## PART 2 | Database authority decides the blast radius

- A compromised application should not automatically inherit the ability to read every retained record.
- Scope a web function's database identity to its real requirements, not to administrative convenience.
- Distinguish authentication, safe query construction and authorization; each needs its own test.
- Encryption at rest does not stop a permitted identity from receiving plaintext.
Caption: Evidence grade: Inferred, not TalkTalk's actual privileges.
Notes: The layered authority model is original analysis supporting [1]; it does not assert the exact privileges used by the application identities.

## PART 2 | Monitoring must end in an accountable decision

- Retaining logs somewhere is not monitoring; relevant events must reach an owner who can act.
- Ask which public routes get unexpected traffic and which identities make unusual database requests.
- A log source needs a coverage statement, retention period, access limits and a way to detect ingestion failure.
- A closed alert should record why activity was benign, the supporting evidence and when to reconsider it.
Caption: Evidence grade: Inferred operational standard.
Notes: The monitoring approach is original analysis; the missed earlier suspicious activity is the context from [1], not a claim about a specific product.

## PART 2 | Preliminary estimates are not a final head count

The 30 October 2015 update was explicitly provisional; the same person can appear in several categories.

| Category | Preliminary figure (30 Oct 2015) |
|---|---|
| Names, email and telephone | Fewer than 1.2 million |
| Obscured payment-card details | Fewer than 28,000 |
| Bank account and sort-code combinations | Fewer than 21,000 |
| Dates of birth | Fewer than 15,000 |
Caption: Evidence grade: Reported provisional company estimates, not final counts.
Notes: Dated company figures from [3]; cards were described as missing their middle six digits, and categories must not be added together.

## PART 2 | Enforcement and company statements answer different questions

Left: What the regulator recorded
- Penalty of GBP 400,000 announced 5 October 2016 under the Data Protection Act.
- Settlement recorded 1 November; an embedded report notes a GBP 320,000 early-payment amount.
- Shortcomings treated as preventable; GDPR discussed only as a future regime.
Right: What TalkTalk stated
- It cooperated, defended prompt communication and cited an ongoing prosecution.
- It took key sites offline, notified authorities after a credible ransom demand, offered credit monitoring.
- The company account does not reverse the regulator's separate preventive-security finding.
Caption: Evidence grade: Confirmed penalty; company statement kept distinct.
Notes: Penalty and legal-context from [7]; settlement and discounted payment from [1]; the company response from [4]. Headline penalty and discounted payment stay distinct.

## PART 2 | Business loss without arithmetic shortcuts

Stat: 15M | Estimated trading impact, GBP, Feb 2016
Stat: 42M | Exceptional attack costs, GBP, report
Stat: 101,000 | Net on-net customer losses, quarter
Stat: 95,000 | Of those, attributed to the attack
- The February update also estimated 40 to 45 million GBP in exceptional costs.
- Total net movement is not the attack-attributed component, nor the number whose records were accessed.
- The 42 million exceptional figure is an accounting category, not a lifetime breach cost or a penalty.
- Show each cost as actual, accrued or forecast; do not sum a broad estimate with a part already inside it.
Caption: Evidence grade: Reported management and accounting estimates.
Notes: Trading impact, exceptional-cost range and attributed churn from [5]; the 42 million exceptional figure and auditor discussion from [6].

## DEFENDER VIEW | An acquisition-to-retirement control process

- At transaction close, inventory each inherited service with enough verified metadata to make reachability and ownership visible.
- Give every inherited service a disposition: retain with verified controls, isolate, or retire with evidence; no indefinite "investigate later".
- Separate four evidence boundaries: discovery, code review, platform state, and database authorization.
- Close corrective actions on evidence of changed behavior, not on a current platform or a rewritten route.
Caption: Evidence grade: Inferred, original defensive proposals.
Notes: The intake, disposition and evidence-boundary model synthesizes [1] and [8]; it is proposed for comparable organizations, not a claim about TalkTalk.

## CROSS-CUTTING THEMES | Where the record is overstated versus understated

Left: Easy to overstate
- Summing records, bank subsets, departures, charges and penalties into one dramatic total.
- Reading a preliminary upper bound as an exact count of affected people.
- Calling the action a GDPR fine, or treating prompt notice as proof of prior safeguards.
Right: Easy to understate
- Four distinct clocks: exposure, detection, containment and notification.
- Inherited infrastructure can outlive the process that first justified it.
- A truncated card fragment can still make an impersonator's story more convincing.
Caption: Evidence grade: editorial corrections the case requires.
Notes: Numbers and definitions from [1][3]; the pre-GDPR legal basis from [7]; harm mechanisms from [10], kept as mechanism not quantified fraud.

## CLOSE | Name the route, justify it, prove the boundary works

- Owning an online service is not the same as governing its routes to customer data.
- Keep records accessed, bank subsets, preliminary estimates, departures, charges and penalties distinct.
- Separate the breach window, discovery, notification and the completion of corrective work.
- The practical test: name every externally reachable service, explain why it exists, and show its boundaries work.
Caption: Evidence grade: case-specific conclusions, bounded to the record.
Notes: Conclusion synthesis across [1] through [8]; precision over a single combined total, and no claim about TalkTalk's present posture.
