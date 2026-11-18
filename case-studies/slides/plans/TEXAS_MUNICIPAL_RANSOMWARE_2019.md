# Slide plan: Texas Municipal Ransomware 2019: A Shared MSP Dependency

- Study: case-studies/TEXAS_MUNICIPAL_RANSOMWARE_2019.md
- Cover title: Texas Municipal Ransomware 2019 / August / A shared MSP dependency
- Subtitle: A coordinated ransomware event hit many Texas local governments at once via a shared managed-service-provider dependency; state reported none paid.
- Published: 18 November 2026
- Notes: The cover sets the frame: one regional event, one shared provider, bounded counts and bounded attribution.

## EXECUTIVE SUMMARY | A regional incident is not a bigger single-org one

- A regional cyber incident is not merely a larger single-organization incident.
- Multiple local governments can need help at once, depend on one provider, and compete for a limited pool of responders.
- The coordination problem can become as important as the malware itself.
- This study uses eight official source records; no ransomware, attacker service, leaked data or recovery tool was accessed.
Caption: Evidence grade: Confirmed framing; eight official sources.
Notes: Executive-assessment framing from [1] through [8]; no exploit code or attacker service run.

## KEY FACTS | Counts, computers, demand and what the state reported paid

Stat: 22 to 23 | Entities: Aug 20 count vs later accounts
Stat: ~740 | Computers in later DIR self-evaluation
Stat: $2.5M | Ransom demanded in DIR self-evaluation
Stat: 0 | Entities the state reported paid
- The August 16, 2019 announcement cited at least twenty affected entities; August 20 confirmed twenty-two.
- Later testimony and the DIR self-evaluation used twenty-three; the consulted record does not explain the change.
- The $2.5 million figure is an attacker demand, not a loss total or an amount paid.
Caption: Evidence grade: Confirmed dated releases; Reported later totals.
Notes: Counts and demand from [1][2][4][5]; no entity paid, per [4][5].

## SHARED DEPENDENCY | A shared MSP became a single point of failure

- The affected entities shared a private managed-services provider.
- The attacker used the provider's server for remote ransomware execution.
- One trusted administrative relationship concentrated authority and created simultaneous demand for recovery.
- The record supports provider-mediated deployment, not a full account of how the provider was first compromised.
Caption: Evidence grade: Confirmed shared provider; initial intrusion not established.
Notes: Shared provider and remote execution from [5]; the single-point framing is original analysis bounded by [5].

## THE STATE ACCOUNT | Dated snapshots, not a final census

Each state update describes what DIR was prepared to say at that point, not a final total.

| Date | What DIR reported | What it did not settle |
|---|---|---|
| Aug 16, 2019 | At least twenty entities affected | A final victim census |
| Aug 20, 2019 | Twenty-two confirmed; state systems unaffected | A named legal attribution |
| Sep 5, 2019 | By Aug 23 all in recovery; over half back to normal | Incident fully eradicated |
Caption: Evidence grade: Confirmed dated updates.
Notes: Snapshots from [1][2][3]; counts and milestones retained as dated, not averaged.

## THE COUNT | Why twenty-two versus twenty-three needs a footnote

- The contemporary August 20 update used twenty-two; later official accounts used twenty-three.
- The consulted records do not explain the change, so no reconciliation is invented.
- Entity, municipality, department and provider customer are not necessarily the same unit.
- Keep the discrepancy visible rather than averaging or selecting the most repeated figure.
Caption: Evidence grade: Confirmed figures; reconciliation not established.
Notes: The 22-versus-23 discrepancy and the counting-unit problem from [2][4][5].

## NO PAYMENT | No ransom paid is not the same as no cost

- The DIR self-evaluation records a $2.5 million demand and no payment.
- A demand is set by the attacker; it is not a loss calculation or a restoration cost.
- Staff time, outside help, replacement equipment and service interruption still impose cost.
- The consulted sources give no audited total, so none is stated here.
Caption: Evidence grade: Confirmed demand and no payment; no audited cost total.
Notes: Demand, no payment and the absent cost total from [5]; demand-versus-loss point is original analysis.

## LATER EVIDENCE | Testimony and the shared-provider finding

- February 2020 Senate testimony described twenty-three entities, no ransom payment and a one-week transition.
- It paired a success account with a warning that a much larger event could exceed the response model.
- The self-evaluation adds about 740 computers and the shared private managed-services provider.
- Encryption disrupted availability; the record does not establish a separate data-theft total.
Caption: Evidence grade: Reported testimony; Confirmed self-evaluation details.
Notes: Testimony from [4]; entity, computer and provider details from [5]; availability kept distinct from theft.

## ATTRIBUTION | Allegations stay allegations

- A November 8, 2021 DOJ announcement linked charges against Yevgeniy Polyanin to Sodinokibi/REvil attacks including Texas entities.
- The August 24, 2021 indictment uses anonymized labels that should not be reverse-mapped to named towns.
- A seizure of alleged proceeds is not evidence that the Texas entities paid or were reimbursed.
- The FBI page lists Polyanin as wanted; no conviction, custody or state direction is asserted.
Caption: Evidence grade: Reported allegations; no conviction established.
Notes: DOJ announcement, indictment and wanted status from [6][7][8]; claimed kept distinct from confirmed.

## DEFENDER VIEW | Provider authority is a concentration of risk

- Evaluate a managed-services relationship as an authority relationship, not only a purchasing arrangement.
- Map what the provider can change and which customers each administrative context can reach.
- Separate accounts may still share one recovery channel or management server, so apparent boundaries can be illusory.
- Reduce unnecessary shared authority while keeping access scoped, attributable, reviewed and recoverable.
Caption: Evidence grade: Original defensive analysis.
Notes: Provider-authority analysis from the study; grounded in the [5] shared-provider finding.

## RECOVERY STATES | States that separate restored from eradicated

This original state model is built for a regional response, not a copy of DIR's internal dashboard.

| State | Evidence required | What it does not mean |
|---|---|---|
| Reported | Identified entity and credible contact | Impact independently confirmed |
| Contained | Defined access or propagation controls | All services are restored |
| Critical service restored | Function-owner acceptance | Every service operates normally |
| Operationally closed | Validated scope and handoff | No long-term work remains |
Caption: Evidence grade: Original review model.
Notes: Condensed from the study's recovery-state table; adapt labels, keep the evidence attached.

## COORDINATION | A shared picture without a shared pool of secrets

- A common operating picture can carry entity, contact, impact, assignment and next milestone.
- Detailed sensitive artifacts can stay in controlled repositories, not a broad mailing list by default.
- Confidence labels separate a local user report, a provider assertion and a responder-verified finding.
- Mutual aid has a capacity limit; a list of willing volunteers is not deployable capacity.
Caption: Evidence grade: Original defensive analysis.
Notes: Common-operating-picture and capacity points are original analysis developed in the study.

## CROSS-CUTTING THEMES | What the retelling overstates versus understates

Left: Easy to overstate
- One blended victim count instead of the dated twenty-two and the later twenty-three.
- A restored critical service read as full, eradicated recovery.
- A seizure or a demand read as proof that entities paid.
Right: Easy to understate
- A shared provider dependency that became a single point of failure.
- No payment did not make the recovery free.
- Attribution is an allegation that developed years after the response.
Caption: Evidence grade: editorial corrections the case requires.
Notes: Overstated and understated contrasts across [2][3][4][5][6]; denominators and stages kept separate.

## CLOSE | Recovery is trustworthy function, not the end of encryption

- Plan for failure of the shared service relationship itself, not only for the malware.
- Keep encryption distinct from data theft, demand distinct from payment, restored distinct from eradicated.
- Keep the entity count bounded and attribution bounded to what the record establishes.
- The strongest response is a traceable account of what changed, what was verified and what is uncertain.
Caption: Evidence grade: conclusion synthesis.
Notes: Conclusion synthesis across [1] through [8]; precision over an invented victim, downtime or cost total.
