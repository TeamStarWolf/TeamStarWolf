# Slide plan: Garmin 2020: Outage Recovery Within the Evidence Boundary

- Study: case-studies/GARMIN_WASTEDLOCKER_2020.md
- Cover title: Garmin 2020 / Connected-Service Recovery / Evidence Boundary
- Subtitle: A confirmed outage and encryption, with data theft, ransom and attribution kept as separate evidence questions the record does not merge.
- Published: 18 November 2026
- Notes: The cover sets the frame: a confirmed outage bounded by its evidence, not a reconstructed intrusion.

## EXECUTIVE SUMMARY | A connected product has many definitions of working

- Local functions can continue while synchronization, accounts, support and communications are unavailable.
- Garmin publicly confirmed encryption of systems and disruption of online services in July 2020.
- WastedLocker research gives context, but a campaign description is not a victim-specific forensic report.
- A service is ready when identities, data, queued work and monitoring support a customer operation without losing or corrupting work.
Caption: Evidence grade: Confirmed outage; no intrusion chain reconstructed.
Notes: Confirmed outage and online-service disruption from [1]; the campaign-versus-victim caution from [3] through [5].

## KEY FACTS | What Garmin confirmed, and what it did not

Stat: 5 | Primary records in the factual base
Stat: Jul 23 | 2020 date Garmin gave for encryption
Stat: 31+ | Orgs in Symantec's campaign set
Stat: None | Ransom payments the record confirms
- Garmin reported no indication that customer data had been accessed, lost or stolen.
- The July statement named no ransomware family, actor or payment.
- Symantec's set predates the disclosure and does not place Garmin among those organizations.
Caption: Evidence grade: Confirmed statements; non-claims kept explicit.
Notes: Encryption date and no-data-theft wording from [1]; the 31-plus campaign set from [3]; payment left unestablished per [1] and [2].

## SCOPE AND METHOD | Five bounded records, no reconstructed intrusion chain

- The factual base is Garmin's SEC statement, its 2020 annual report, and research from Symantec, Unit 42 and Microsoft.
- No Garmin systems, customer records, malware samples or leaked materials were accessed.
- The reviewed records do not establish entry method, responsible individuals, a demand, a payment or decryption mechanics.
- Recommendations do not imply Garmin lacked the listed controls, and one outcome does not generalize to other organizations.
Caption: Evidence grade: Confirmed method statement; scope bounded.
Notes: The five-record base and access limits from [1] through [5]; the annual report checked at its incident risk passage, page 16, per [2].

## PART 1 | A chronology that does not invent missing events

Each row pairs a public record with what it does not establish.

| Date or period | Public record | What it does not establish |
|---|---|---|
| June 2020 | Vendor campaign observations preceded the outage | Garmin's compromise date or membership in that set |
| July 23, 2020 | Encryption date specified by Garmin | First unauthorized access or attacker dwell time |
| July 27, 2020 | Company statement and restoration expectation | An exact completion time for every service |
| July 29, 2020 | Microsoft's WastedLocker entry | A company-confirmed malware attribution |
| 2020 annual report | Retrospective materiality and investigation | Zero cost or a public ransom figure |
Caption: Evidence grade: Confirmed dates; non-claims kept explicit.
Notes: Dates and the non-establishing column from [1], [2], [3] and [5]; separate clocks for first access and customer impact are advised in the study.

## PART 1 | Attribution, family label and payment answer different questions

- A sample can resemble a known family without identifying the person who ran it.
- A vendor can associate a family with a group without investigating every incident carrying that label.
- The study does not establish whether a payment occurred, what amount, or whether an intermediary was involved.
- A suspected actor links to sanctions questions; any live payment decision needs current legal advice, which this history does not supply.
Caption: Evidence grade: Reported context; attribution and payment left bounded.
Notes: Family-versus-operator distinctions from [3] through [5]; the payment and sanctions caution kept as a reported consideration, not a confirmed narrative, per [2] and [3].

## PART 2 | Identify the actual failure boundary first

- Divide the service into local functions, identity, ingestion, processing, presentation, support and administrative control.
- A customer may create a local record yet be unable to upload it; an upload may succeed while presentation is delayed.
- Build the inventory around a concrete operation, naming where the record exists and which identity authorizes each step.
- Define degraded modes in normal testing, including which operation a customer should avoid because retrying is not safe.
Caption: Evidence grade: Original defensive analysis, not Garmin's architecture.
Notes: The component model and degraded-mode questions are original analysis; the study states this is not a representation of Garmin's internal systems.

## PART 2 | Availability, integrity and confidentiality stay separate

- Unavailable information is not necessarily deleted, and readable information is not necessarily trustworthy.
- Absence of evidence of theft is not proof that no access occurred; record each as its own finding.
- Measure availability by operation completion, integrity by correct account association, confidentiality by access evidence.
- A single green status indicator cannot answer all three questions at once.
Caption: Evidence grade: Inferred discipline drawn from the record.
Notes: The three-way separation is the study's analysis; the no-data-theft statements it bounds come from [1] and [2].

## PART 2 | Recovery is a dependency problem, not a server count

- Start from a minimum useful customer operation and work backward through its dependencies.
- Restoring application data while keeping suspect administrative authority can reintroduce risk.
- A backup can carry the needed data alongside an unwanted scheduled action or outdated access grant.
- Define a stop condition before reopening, so the authority to pause does not require improvisation.
Caption: Evidence grade: Original defensive analysis.
Notes: Identity, configuration baseline and stop-condition guidance are original analysis in the study, not a described Garmin recovery sequence.

## PART 2 | Backlog replay is the second incident to prevent

- A long outage leaves work waiting on devices, in upload buffers, in queues and in downstream processing.
- Reconciliation begins with ownership: the authoritative identifier and the system deciding whether work was processed.
- Preserve the time an activity occurred, was received and was processed; sorting by arrival alone misleads.
- A shrinking queue is encouraging but not sufficient; rejected records and silent drops also shrink it.
Caption: Evidence grade: Original defensive analysis.
Notes: Duplicate handling, out-of-order replay and controlled-batch release are the study's proposed framework; it declines to recommend reset or reinstall actions for Garmin products.

## DEFENDER VIEW | Detect the intrusion before visible encryption

- Treat ransomware as an intrusion problem, monitoring administrative behavior alongside endpoint alerts.
- Tie each detection to a response owner and a feasible next step, not a record no one acts on.
- Retain evidence outside the administrative identity most likely to be affected, including retention controls.
- Do not treat an old hash or filename as the whole strategy; an operator can change the visible artifact.
Caption: Evidence grade: Inferred framework; not an assertion about Garmin.
Notes: The campaign reports motivating intrusion-first detection are [3] through [5]; the design is proposed, not a claim that a specific event occurred inside Garmin.

## ACCEPTANCE | A proposed recovery acceptance record

A working record, not a regulatory checklist or a claim about Garmin's process.

| Acceptance question | Evidence to retain | Accountable role |
|---|---|---|
| Can the customer operation complete? | Documented end-to-end test and result | Service owner |
| Is administrative access trustworthy? | Reviewed identities and approved exceptions | Identity and security leads |
| Is restored information correct? | Reconciliation, integrity checks, open discrepancies | Data owner |
| Is accumulated work handled safely? | Replay results, duplicates, rejected-item accounting | Processing owner |
| Does public status match the service? | Timestamped approval and support instructions | Communications lead |
Caption: Evidence grade: A proposed working record, not Garmin's process.
Notes: Condensed from the study's acceptance table; each exception needs an owner, a reason and a review deadline, and acceptance stays conditional on the tested scope.

## CROSS-CUTTING THEMES | What the record overstates versus understates

Left: Easy to overstate
- An outage as proof that customer data was stolen or every product failed.
- A malware family name as a company-confirmed attribution.
- A restored server as a ready, trusted customer service.
Right: Easy to understate
- A connected product has several definitions of working at once.
- Availability, integrity and confidentiality need separate evidence.
- Backlog replay can create a second incident after reopening.
Caption: Evidence grade: Editorial corrections the case requires.
Notes: The affected-versus-compromised and claimed-versus-confirmed contrasts rest on [1] and [2]; the campaign-set caution ties to [3].

## CLOSE | A bounded account beats a dramatic reconstruction

- The strongest lesson is to separate the observed outage, the forensic statements and the surrounding research.
- Keep encryption distinct from data theft, and ransom demanded distinct from paid distinct from total cost.
- Keep services restored distinct from the incident eradicated, and claimed distinct from confirmed.
- Deliver a service that recovers without asking customers to guess what happened to their work.
Caption: Evidence grade: Case-specific conclusions, claims bounded.
Notes: Conclusion synthesis across [1] through [5]; preserve the evidence labels in title, summary, timeline and slides, and add no unverified ransom figure.
