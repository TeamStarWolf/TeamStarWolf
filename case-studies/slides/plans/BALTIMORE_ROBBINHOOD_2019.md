# Slide plan: Baltimore and RobbinHood, 2019: A Transaction Crisis

- Study: case-studies/BALTIMORE_ROBBINHOOD_2019.md
- Cover title: Baltimore and RobbinHood / May 2019 / A transaction crisis
- Subtitle: A ransomware outage became a transaction crisis; keep encryption distinct from theft, and three cost numbers distinct from one another.
- Published: 18 November 2026
- Notes: The cover sets the frame: a municipal availability event that became a crisis of trusted transactions, read from bounded sources.

## EXECUTIVE SUMMARY | An outage became a transaction crisis

- Baltimore's 2019 RobbinHood attack shows how municipal technology connects to transactions beyond city hall, not just employees.
- Keep encryption, an availability harm, distinct from data theft, a confidentiality harm.
- Early estimate, spending authority and later loss statement measure different things and keep their own labels.
- The sources reviewed do not justify repeating EternalBlue as Baltimore's established entry mechanism.
Caption: Evidence grade: Bounded historical account plus an original framework.
Notes: Executive framing across [1] through [8]; no ransomware was obtained or executed and no victim records were inspected.

## KEY FACTS | Discovery, partial access, and a 2025 plea

Stat: May 7 | 2019 discovery, announced May 17
Stat: 65% | Employees back on computers, Jun 10
Stat: May 2025 | DOJ guilty-plea announcement
- The incident was discovered on 7 May 2019 and described in city updates on 17 May and 10 June.
- RobbinHood is the ransomware family named in the record; Sina Gholinejad pleaded guilty in May 2025.
- The 10 June update's 65 percent is employee access, not a share of all city functions restored.
Caption: Evidence grade: Confirmed, dated records.
Notes: Discovery and service dates from [1] and [2]; the plea milestone from [5].

## PART 1 | Keep encryption, theft, demand and paid distinct

- Encryption is an availability harm and data theft is a confidentiality harm; keep them in separate fields.
- Ransom demanded, ransom paid and total recovery cost are three different quantities, not one headline.
- "Systems restored" is not the same claim as "incident eradicated."
- Keep affected distinct from compromised, and claimed distinct from confirmed.
Caption: Evidence grade: Confirmed definitions; no paid-ransom figure is asserted.
Notes: Evidence-level discipline drawn from the study; the record does not establish a confirmed paid ransom [1][5].

## EVIDENCE | What the city communications establish

- The 17 May update described containment, manual alternatives and a temporary property-transaction process.
- That workaround was a dated policy response, not evidence that property debts had ceased to exist.
- The 10 June update reported 65 percent employee access while recovery continued, and a cleared property backlog.
- One cleared backlog does not establish the absence of all other backlogs.
Caption: Evidence grade: Confirmed, dated city updates.
Notes: Service conditions and the property workaround from [1]; employee access and the cleared backlog from [2].

## COST | Three numbers, three meanings

Stat: ~$18M | Early May 2019 estimate (Jan 2020 note)
Stat: $10M | Enacted supplementary appropriation
Stat: $19M+ | DOJ stated Baltimore losses, 2025
- The early estimate combined roughly $10M for network restoration and repair with roughly $8M in potential lost or delayed revenue.
- The $10M appropriation is spending authority, not proof of invoices paid or final loss.
- The DOJ figure is a later loss statement; the three belong in separate rows, not one sum.
Caption: Evidence grade: Confirmed source figures; the reconciliation is analysis.
Notes: Estimate from [3], appropriation from [4], DOJ loss statement from [5]; the numbers are not directly additive.

## COST RECONCILIATION | Reconcile categories before adding totals

- Delayed collections can affect cash flow without becoming permanent losses.
- Adding the appropriation to the early estimate risks counting the same recovery work twice.
- A prosecution loss statement may use a methodology that differs from municipal accounting.
- Attribute the later figure to DOJ and preserve the earlier number as a historical projection.
Caption: Evidence grade: Inferred editorial guidance, bounded to the sources.
Notes: Double-counting and category discipline from [3], [4] and [5]; no new final total is asserted.

## TIMELINE | Separate operational, financial and legal events

Each row carries a bounded event and what it does not establish.

| Period | Bounded event | Does not establish |
|---|---|---|
| May 2019 | Discovery, containment, temporary arrangements | A complete intrusion chronology |
| June 2019 | Partial employee access, service-specific update | Universal operational recovery |
| 2019 | Supplementary response-and-recovery appropriation | Final expenditure or loss total |
| Jan 2020 | Fiscal note recounts an early cost projection | Audited final accounting |
| May 2025 | DOJ announces guilty plea and loss statement | A present sentence or final appeal |
Caption: Evidence grade: Confirmed dates; non-claims kept explicit.
Notes: Operational rows from [1] and [2], financial rows from [3] and [4], legal row from [5]; discovery is not the first moment of unauthorized activity.

## TECHNICAL CONTEXT | A contested EternalBlue claim stays contested

- SentinelLabs analyzed a Go-based sample with hybrid encryption that interferes with backup and other services.
- The analyzed sample showed no autonomous network spreading; its deployment discussion was an inference.
- A later note on that page rejects the EternalBlue and BlueKeep propagation claims and refers to a city statement.
- Treat EternalBlue as a reported, contested claim, not Baltimore's established entry mechanism.
Caption: Evidence grade: Reported and contested; initial vector unresolved.
Notes: Sample analysis and the rejected propagation claims from [7]; the NHS family advisory predates the incident [8].

## TECHNICAL | Access, deployment and impact are different

- Access is reaching an environment without authorization; deployment places or starts a payload; impact hits data and services.
- A malware sample can reveal impact behavior while showing little about the access step that preceded it.
- Absence of a self-spreading exploit in the executable does not prove none was used elsewhere.
- A famous exploit existing does not establish its use; network and host evidence are required.
Caption: Evidence grade: Inferred defensive distinction.
Notes: Access, deployment and impact separation drawn from [7] and [8]; later techniques must not be backdated to 2019.

## FRAMEWORK | Transaction continuity has four layers

- Availability: a usable channel exists and responds for the intended population.
- Authority: the staff member or system is actually permitted to make the decision.
- Integrity: provisional status, source and history travel with each record.
- Finality: parties know what is completed and what remains conditional.
Caption: Evidence grade: Original analytic framework.
Notes: Original model, not a claim about Baltimore's response plan; reopening a webpage is not proof a transaction is safe to complete.

## DEFENDER VIEW | Provisional data must not look verified

- A blank field, a zero value and a confirmed absence are not the same thing.
- Use explicit status fields so uncertainty survives export and handoff to another party.
- Record the earlier value, the corrected value, the reason and the authority for each change.
- Do not assume the newest timestamp is authoritative when restoring from multiple sources.
Caption: Evidence grade: Original defensive analysis.
Notes: Synthesized from the study's provisional-data guidance; intended for authorized environments with synthetic data.

## METRICS | Metrics that make the hidden work visible

A useful definition beats a misleading shortcut for each measure.

| Metric | Definition that helps | Misleading shortcut |
|---|---|---|
| Service availability | Specific function usable via approved channel | Website responds |
| Data confidence | Records validated for the intended transaction | Database mounted |
| Financial exposure | Dated categories with overlap reconciled | All amounts added together |
| Workaround integrity | Provisional status and authority preserved | Paper form exists |
| Recovery closure | Temporary access and rules retired with evidence | Incident bridge ends |
Caption: Evidence grade: Original review tool; adapt the rows.
Notes: Condensed from the study's metrics table; every measure should state its denominator and confidence.

## CROSS-CUTTING THEMES | What the record overstates versus understates

Left: Easy to overstate
- Adding the estimate, the appropriation and the DOJ figure into one total.
- Repeating EternalBlue as Baltimore's established entry mechanism.
- Reading 65 percent employee access as all city functions restored.
Right: Easy to understate
- Three cost numbers that measure genuinely different things.
- A campaign-level theft statement is not a local breach inventory.
- Temporary workarounds create real reconciliation obligations.
Caption: Evidence grade: Editorial corrections the case requires.
Notes: Cost separations from [3] and [4], entry-vector caution from [7], campaign-versus-local point from [5] and [6].

## CLOSE | Precision beats a single dramatic number

- A municipal outage is a disruption to trusted transactions, not only encrypted machines.
- Keep encryption distinct from theft, and the three cost numbers in separate rows.
- Keep EternalBlue bounded as contested, and campaign-level theft distinct from a local inventory.
- Recovery succeeds when the public can rely on the transaction again.
Caption: Evidence grade: Case-specific conclusions, claims bounded to their sources.
Notes: Conclusion synthesis across [1] through [8]; keep source dates, scope and limitations visible in every format.
