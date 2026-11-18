# Slide plan: Atlanta and SamSam, 2018: Recovery Is a Service Capability

- Study: case-studies/ATLANTA_SAMSAM_2018.md
- Cover title: Atlanta and SamSam / March 2018 / Recovery as a service
- Subtitle: A municipal ransomware incident disrupts records, deadlines and services; keep encryption, data theft, ransom and recovery cost distinct.
- Published: 18 November 2026
- Notes: The cover sets the frame: a bounded municipal incident and a recovery model, not a total-collapse story.

## EXECUTIVE SUMMARY | Restoring a server is not restoring a service

- A municipal ransomware incident disrupts records, people, deadlines and public services, not only endpoints.
- A functioning login page does not prove records are complete or that a payment will not be processed twice.
- The record supports serious disruption, not a claim that every city function was destroyed.
- Recovery is modeled as separate workstreams: containment, clean restoration, service acceptance, reconciliation and communication.
Caption: Evidence grade: Confirmed disruption; no total citywide collapse established.
Notes: Executive framing from the study; sources are [1] through [4], with no reconstruction of the intrusion.

## KEY FACTS | The Atlanta figures, bounded to their sources

Stat: 3,789 | Affected city computers (DOJ)
Stat: 6 BTC | Demand for the whole group
Stat: $51k | Demand the city refused to pay
Stat: $7.2M | Recovery cost to date, 2019
- The DOJ account lists roughly 3,789 affected computers and 0.8 Bitcoin per computer or six Bitcoin for the group.
- The city did not pay, and the payment-related webpage later became unavailable.
- The mayor described a roughly USD51,000 demand and about USD7.2 million in recovery cost to that point.
- A demand is not a cost; the dollar figure is dated and explicitly to date, not a final audited ledger.
Caption: Evidence grade: Confirmed charging and testimony figures.
Notes: Computer count and demand from [1]; recovery cost, refusal and partial insurance from [3].

## PART 1 | Atlanta's numbers are not the campaign's numbers

Stat: 200+ | Campaign victims alleged
Stat: $6M+ | Ransom receipts alleged
Stat: $30M+ | Additional losses alleged
- The New Jersey indictment alleges a campaign of more than 200 victims, over USD6 million in receipts and over USD30 million in further losses.
- Those are campaign-wide allegations, not Atlanta's cost.
- The indictment places Atlanta activity on 22 March 2018 but does not assign every campaign technique to every city computer.
- An indictment contains allegations, not a conviction.
Caption: Evidence grade: Reported allegations, campaign-wide scope.
Notes: Campaign totals and the Atlanta date from [2]; a campaign model gives hypotheses, not host conclusions.

## PART 1 | The mayor's account separates service states

- Written testimony dated 25 June 2019 described disruption to municipal court hearings and ATL311.
- It stated that emergency services and the water supply were not affected.
- It reported about USD7.2 million in recovery cost to date, anticipated further cost and partial insurance reimbursement.
- These are dated statements, not a final ledger or proof that every function supporting emergency services was untouched.
Caption: Evidence grade: Reported testimony, explicitly to date.
Notes: Service effects, unaffected services and recovery cost from [3].

## PART 1 | Financial facilitation is not state direction

- Treasury's 28 November 2018 action designated two Iran-based facilitators tied to converting SamSam proceeds.
- It distinguished transactions associated with the addresses from transactions specifically connected to the ransomware.
- The designation supplies facilitation context; it does not establish that a national government ordered the Atlanta incident.
- Criminal attribution and geopolitical attribution require different evidence.
Caption: Evidence grade: Confirmed designation; no state-direction finding.
Notes: Designation and address caveat from [4]; attribution kept to what the record supports.

## TIMELINE | Each timestamp describes one bounded event

The table names what each date establishes and where interpretation must stop.

| Period | Evidence-backed milestone | Interpretation boundary |
|---|---|---|
| March 2018 | Intrusion and encryption activity in the federal account | Not a complete host-by-host chronology |
| 22 March 2018 | Major operational disruption described by the mayor | Services held different operational states |
| November 2018 | Broader prosecution and Treasury action announced | Campaign totals are not city totals |
| December 2018 | Atlanta-specific charges announced | Charges do not establish guilt at trial |
| June 2019 | Mayor reports service effects and spend to date | Neither final audited cost nor current security |
Caption: Evidence grade: Confirmed dates; boundaries kept explicit.
Notes: Condensed from the study timeline across [1] through [4]; the announcement date is not the first day of access.

## EVIDENCE BOUNDARIES | What the reviewed record does not establish

- No single named vulnerability is established as Atlanta's initial access route; generic phishing advice is not a forensic finding.
- Encryption is not confirmed data theft, and absence of an exfiltration finding is not proof confidentiality held.
- No final all-inclusive recovery cost is established; a demand, an invoice, an appropriation and a forecast are different objects.
- A charge identifying individuals does not license conclusions about nationality or state sponsorship.
Caption: Evidence grade: Inferred boundaries drawn from the sources.
Notes: Non-claims from the study; keep affected versus compromised and claimed versus confirmed distinct.

## ANALYTICAL MODEL | Five recovery states, often compressed to one

The model separates five states that the single word restored usually hides.

| State | What it means | Not the same as |
|---|---|---|
| Contained | Justified limits on further access, with evidence | Switching everything off |
| Technically rebuilt | System rebuilt from an acceptable source | Every restored record trustworthy |
| Operationally accepted | Owner verifies safe representative work | A successful login screen |
| Reconciled | Backlog matched, duplicates identified | A service merely available |
| Stabilized | Monitoring and staffing sustainable | Nightly heroics continuing |
Caption: Evidence grade: Original defensive model.
Notes: The five states are original analysis, not a reconstruction of Atlanta's internal response.

## DEFENDER VIEW | Start with services, not a device count

- An asset inventory is necessary but is not a recovery priority list; build a service map to outcomes.
- For each service record the owner, minimum viable function, consequence of delay and population affected.
- Include residents without reliable internet, people with disabilities and those who need translated information.
- Keep an approved offline copy of the plan; its accessibility is itself a dependency to test.
Caption: Evidence grade: Original defensive analysis.
Notes: Service-first prioritization from the study; no Atlanta internal data is implied.

## DEFENDER VIEW | Backups prove a service, not a successful job

- A backup dashboard shows that copying occurred, not that a service can be restored.
- A meaningful test rebuilds an isolated environment and validates the data that real work needs.
- Protect both the stored data and the authority that can modify or delete it.
- A recovery point needs a trust assessment; record why the chosen version is acceptable.
Caption: Evidence grade: Original defensive analysis.
Notes: Backup validation discipline from the study; exercises use synthetic or protected data only.

## RECONCILIATION | Reconciliation is a distinct recovery programme

- Begin with a defined cutover boundary; departments may not share one citywide timestamp.
- Match temporary transactions to restored records using approved identifiers, and send ambiguous matches to review.
- Define duplicate handling before bulk entry so one resident does not inherit another's payment or appointment.
- Closure needs a measurable standard: unresolved items, aging and consequential cases reported separately.
Caption: Evidence grade: Original defensive analysis.
Notes: Reconciliation workstream from the study; a declining total alone is not closure.

## DEFENDER VIEW | Measure residents recovering, not machines on

Each measure needs a denominator; the substitute column is the misleading shortcut.

| Measure | Useful definition | Misleading substitute |
|---|---|---|
| Service acceptance | Owner validates end-to-end work | Servers powered on |
| Recovery readiness | Isolated restoration with documented dependencies | Backup jobs marked successful |
| Backlog resolution | Temporary transactions reconciled, exceptions tracked | Number of forms entered |
| Access control | High-impact authority verified, exceptions owned | Password-reset count |
| Financial visibility | Dated commitments separated by purpose | One unexplained headline total |
Caption: Evidence grade: Original metrics framework.
Notes: Condensed from the study's metrics table; testing three services does not establish readiness for fifty.

## CROSS-CUTTING THEMES | Where the record is overstated versus understated

Left: Easy to overstate
- Every city function destroyed, or all city data stolen.
- Campaign totals read as Atlanta's own cost.
- A ransom demand treated as the cost of the incident.
Right: Easy to understate
- A serious, dated public-service disruption.
- Reconciliation as real recovery work, not optional cleanup.
- Attribution bounded to a criminal charge, not state direction.
Caption: Evidence grade: editorial corrections the case requires.
Notes: Overstated and understated contrasts drawn from [1] through [4]; keep denominators and accounting objects separate.

## CLOSE | Municipal resilience is a service capability

- Technical restoration matters, but residents experience recovery through accurate records, fair process and reliable information.
- Keep encryption, data theft, ransom demanded, ransom paid and recovery cost in separate fields.
- Keep systems restored distinct from incident closed, and affected distinct from compromised.
- The city is better prepared when it can show who owns each decision and what evidence supports reopening.
Caption: Evidence grade: case-specific conclusions, claims bounded.
Notes: Conclusion synthesis across the study; rests on [1] through [4].
