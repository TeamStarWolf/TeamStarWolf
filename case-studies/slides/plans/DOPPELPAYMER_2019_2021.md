# Slide plan: DoppelPaymer 2019-2021: One Label, Three Separate Problems

- Study: case-studies/DOPPELPAYMER_2019_2021.md
- Cover title: DoppelPaymer 2019-2021 / Code fork, service disruption / and personal coercion
- Subtitle: Code lineage, service disruption and personal coercion are different problems needing different evidence; claimed and confirmed stay apart.
- Published: 18 November 2026
- Notes: The cover sets the frame: one family label covering three problems that need different evidence and different responses.

## EXECUTIVE SUMMARY | Three separate problems under one family label

- DoppelPaymer's technical record concerns a code fork; its operational record concerns interrupted services people depend on.
- The coercion record includes efforts to move pressure from an organization's systems to individual employees.
- This study does not claim ransomware caused a reported patient's death; the FBI account does not support that.
- Raids and warrants are consequential investigative events, not convictions or complete eradication.
Caption: Evidence grade: Confirmed fork; disruption Reported; no death causation claimed.
Notes: Executive-assessment framing; the primary record is [1] through [9], with no malware, stolen data or live incident accessed.

## KEY FACTS | A fork in 2019, disruption in 2020, searches in 2023

Stat: Jul 12 | CrowdStrike code-fork research, 2019
Stat: Dec 10 | FBI notification, indexed Dec 15, 2020
Stat: 13 days | Dusseldorf emergency intake diverted
Stat: 600+ | affected parties in 2023 police grouping
- CrowdStrike reported AES-256 with RSA-2048, while NHS Digital listed RSA-4096 for DoppelPaymer.
- Recovered builds dated to April 2019 while the first known victims dated to June.
- The case is centered on 2019-2021; the 2023 police operation is presented as a dated afterword.
Caption: Evidence grade: Confirmed dated advisories and statements.
Notes: Dates and figures from [1][2][4][5]; the 600+ figure spans several ransomware names and is not DoppelPaymer-only [5].

## PART 1 | A code fork is a technical relationship, not an identity

- CrowdStrike described DoppelPaymer as a BitPaymer code fork on July 12, 2019. [1]
- Recovered builds dated to April 2019 and first known victims to June, so build, discovery and first incident differ.
- A code fork shows a shared code base diverged; it does not by itself identify who operates either branch.
- Containment can proceed on observed behavior while actor attribution stays a provisional hypothesis.
Caption: Evidence grade: Confirmed fork finding; the actor split is a hypothesis.
Notes: Fork finding, build and victim dates, and the separate-operation assessment from [1]; the earliest sample available is not the earliest that ever existed.

## PART 1 | Hybrid encryption, and one unresolved key-size discrepancy

- CrowdStrike reported threaded encryption, a required execution argument and use of ProcessHacker components to interrupt selected processes. [1]
- Its comparison table specified AES-256 with RSA-2048 for the analyzed DoppelPaymer, versus RSA-4096 for the compared BitPaymer.
- NHS Digital's July 18, 2019 alert described AES-256 but listed RSA-4096 for DoppelPaymer; this study preserves that discrepancy. [2]
- These are specimen-level findings; a recovery team would need specimen-specific verification, not a family-wide key size.
Caption: Evidence grade: Confirmed specimen findings; one key-size discrepancy unresolved.
Notes: Technical details from [1]; distribution and key-size caveats from [2]. Failure to run in one sandbox does not prove a program harmless, and no exploit code is reproduced.

## PART 1 | Related-family context from ANSSI stays bounded

- ANSSI's October 21, 2019 BitPaymer/IEncrypt report described manually operated intrusions, with privileged-account access important before deployment. [3]
- It distinguished disconnected backups from replicated data that attackers could also reach.
- Its DoppelPaymer subsection attributed the code-fork interpretation to CrowdStrike, not independent analysis.
- Most findings concern BitPaymer and cannot be copied wholesale into a DoppelPaymer timeline.
Caption: Evidence grade: Reported related-family context; not transferable to every incident.
Notes: Access, recovery-architecture and attribution points from [3]; a binary, a campaign and an operator network are not interchangeable units.

## PART 2 | Counting encrypted machines understates service impact

- The FBI notification, dated December 10, 2020 and indexed December 15, described impacts across healthcare, emergency services and education. [4]
- Examples included inaccessible computer-aided dispatch and several weeks of restoration at a medical center with offsite backups.
- It reported telephone intimidation, including threats involving an employee and relatives.
- A demand amount is what criminals requested; it does not establish payment, recovery cost or damage.
Caption: Evidence grade: Reported examples; different organizations and different intervals.
Notes: Impact examples, the dispatch dependency and the demand-versus-payment distinction from [4]; a small set of systems can support a consequential workflow.

## PART 2 | Dusseldorf: differentiated services and a staged recovery

UKD's own dated statements kept service states, cause and recovery separate rather than collapsing them into one "offline" label.

| Date (2020) | UKD statement | Boundary preserved |
|---|---|---|
| Sep 10-11 | Emergency intake withdrawn | Existing inpatient care still assured |
| Sep 17 | Data access restored | Not a final forensic certification |
| Sep 18 | Patch installed on release day | No negligence finding established |
| Sep 23 | Emergency intake resumed | After 13 days of routine diversion |
| Oct 12 | Occupancy back to 800-900 | Some IT still unrestored |
Caption: Evidence grade: Confirmed dated hospital statements; each bounded to its moment.
Notes: Service states and milestones from [6][7][8][9]; no specific ransom demand reported at UKD [7], and the undisclosed incident-command checklist is not reproduced [9].

## PART 2 | Patient harm: chronology does not establish causation

- The FBI discussed a German hospital disruption and a patient diverted elsewhere who later died. [4]
- German authorities did not hold the ransomware actors responsible; the patient's condition meant death likely would have occurred without diversion.
- "A patient died after a diversion" is a chronological statement; "the ransomware caused the death" is a causal claim needing more evidence.
- This study does not present a proven first death caused by ransomware.
Caption: Evidence grade: Reported disruption with the causation qualification preserved.
Notes: The disruption, the qualification and the open-source attribution from [4]; the operational lesson does not depend on the stronger claim.

## PART 2 | The 2023 enforcement afterword stays dated, not final

- Landeskriminalamt Nordrhein-Westfalen's March 6, 2023 statement described coordinated searches on February 28 in Germany and Ukraine and warrants against suspects. [5]
- The network used several ransomware names, so "more than 600 affected parties" is not a clean DoppelPaymer-only count.
- This study treats searches, warrants and allegations as dated events, not convictions or complete eradication.
- The 2019 vendor taxonomy and the 2023 investigative grouping answer different questions.
Caption: Evidence grade: Reported allegations and investigative action; not convictions.
Notes: Original police content distributed by news aktuell [5]; wanted posters and personal identifiers are not reproduced, and current legal status needs a separate review.

## DEFENDER VIEW | Protect selected processes and dispatch continuity

Left: Selected-process interruption
- Know which processes sustain protection, backups and critical applications, and who can stop or reconfigure them.
- Compare unexpected changes with approved maintenance records; a lost sensor is not evidence of a healthy endpoint.
- ProcessHacker is not inherently malicious; the concern is unauthorized use, authority and effect.
Right: Dispatch continuity
- Dispatch depends on identity, location data, communications and the ability to record decisions, not just desktops.
- A degraded mode must define available information and the reconciliation work it creates.
- External helpers may share the same provider or identity system; test that assumption for the real failure.
Caption: Evidence grade: Original defensive analysis; the technical theme follows [1] and [4].
Notes: Process-interruption theme from [1], dispatch dependency motivated by [4]; no claim about the undisclosed architecture of the counties in the FBI examples.

## DEFENDER VIEW | Telephone coercion changes the response audience

- A threat delivered directly to an employee can bypass the organization's normal incident-management structure.
- Provide a clear internal route to report threatening contact and preserve information; urgent threats go through established emergency procedures.
- Staff should not negotiate, authenticate the caller or investigate relatives' exposure personally.
- Limit circulation of personal details; caller claims and caller identity stay separate in the evidence record.
Caption: Evidence grade: Original organizational analysis; the FBI example motivates it.
Notes: The coercion example is from [4]; this document does not recommend contacting or paying an extortionist, and does not claim every victim received calls.

## DEFENDER VIEW | Recovery is a service validation project

- Distinguish available backups from usable recovery; existence and speed are different properties. [4]
- Define what evidence demonstrates correct behavior before reopening a service; starting a server is only one part.
- A recovered application that trusts compromised accounts can remain exposed, so identity restoration needs explicit attention.
- Separate waiting for equipment, rebuilding infrastructure, restoring data and validating business processes in the timeline.
Caption: Evidence grade: Inferred recovery guidance drawn from the record.
Notes: The extended restoration example is from [4]; the acceptance criteria and timeline separation are original analysis, with checks chosen per service.

## CROSS-CUTTING THEMES | Overstated versus understated in the retelling

Left: Easy to overstate
- A proven first ransomware death; the FBI account does not support it.
- "More than 600 victims" read as a DoppelPaymer-only count.
- A ransom demand treated as payment, loss or total damage.
Right: Easy to understate
- Serious, dated disruption to emergency and clinical workflows.
- Coercion aimed at individual employees, beyond the encrypted device.
- A known backup can still require a substantial restoration effort.
Caption: Evidence grade: editorial corrections the case requires.
Notes: Contrasts drawn across [4][5][6][9]; keep claimed separate from confirmed, and affiliate structure separate from one named actor.

## CLOSE | Differentiated evidence beats a single simplified narrative

- Code similarities do not resolve every operator question, and shared names can carry different scopes.
- A service outage can be serious without an exaggerated causal claim about a death.
- Assess artifacts and access separately from actor identity; validate essential services and their degraded alternatives.
- Close explicit acceptance criteria rather than treating the disappearance of a ransom note as the end of the event.
Caption: Evidence grade: a conclusion synthesis.
Notes: Final-assessment synthesis across [1] through [9]; the primary record supplies a bounded foundation for better questions, not invented fact.
