# Slide plan: Locky 2016: Ransomware Distribution as an Adaptable System

- Study: case-studies/LOCKY_2016.md
- Cover title: Locky 2016 / Ransomware Distribution / As an Adaptable System
- Subtitle: One ransomware family with many delivery routes; why prevention, containment and recovery are separate responsibilities with separate evidence.
- Published: 18 November 2026
- Notes: The cover sets the frame: an adaptable delivery system documented across sources, not one victim's incident.

## EXECUTIVE SUMMARY | Adaptive distribution, not one lure or one operator

- Locky challenges the idea that a ransomware family has one delivery method, one operator and one simple preventive control.
- Reporting described malicious documents, script attachments, intermediate downloaders and exploit-kit delivery, different routes to one damaging outcome.
- This is a campaign and malware-family study, not one victim's complete incident; it estimates no infections, revenue or total loss.
- Prevention, containment and restoration are separate responsibilities; removing a malicious executable does not reconstruct encrypted data.
Caption: Evidence grade: Confirmed delivery observations; no victim total claimed.
Notes: Executive-assessment framing; sources are [1] through [5], with no malware executed [1][5].

## KEY FACTS | Dated observations, deliberately no global totals

Stat: Feb 16 | Proofpoint's first observation, 2016
Stat: Mar 31 | Compressed-script campaign observed
Stat: Apr 1 | Canadian alert AL16-005
Stat: 5 | Primary sources behind the account
- Delivery routes reported include macro Word documents, script attachments, the RockLoader downloader and exploit kits.
- The study estimates no worldwide infections, ransom revenue or total financial loss, and adds no number across units.
- "Claimed by operators" stays separate from "confirmed"; payment was not verified to return a decryptor.
Caption: Evidence grade: Confirmed, dated vendor and government records.
Notes: Dates from [1][2][3][4]; the five primary sources include Microsoft's family entry [5].

## PART 1 | What the early reporting established

- Proofpoint's initial report described invoice-themed Word attachments whose macros retrieved Locky.
- It connected the observed spam to infrastructure used for Dridex campaigns and noted a related Neutrino observation.
- A common actor or affiliate distribution was treated as a possible explanation, not a proven shared identity.
- It documented ransom instructions and encryption, while stating payment was not confirmed to produce a decryptor.
Caption: Evidence grade: Reported vendor observations; association, not attribution.
Notes: Invoice macros, the Dridex-infrastructure link and the payment caveat all from [1].

## PART 1 | Adaptation ran across the delivery chain

- A later Proofpoint investigation documented changed attachments and an intermediate downloader called RockLoader.
- Its March 31 observation involved compressed JavaScript, with variation in archive types and filenames.
- Unit 42 separately documented Nuclear exploit-kit traffic delivering Locky on March 15 and 16.
- The useful finding is adaptation across the chain, not that every infection passed through one route.
Caption: Evidence grade: Reported, per-campaign observations.
Notes: RockLoader and compressed script from [2]; Nuclear exploit-kit delivery from [3].

## PART 1 | A bounded observation timeline

This is an observation timeline; it does not fill gaps with presumed attacker actions.

| Date | Evidence | What it does not establish |
|---|---|---|
| Feb 16, 2016 | Proofpoint's stated first observation | First observation by every researcher |
| Mar 15-16, 2016 | Unit 42 Nuclear delivery | The only exploit-kit campaign |
| Mar 31, 2016 | Proofpoint compressed-script campaign | All delivery switched permanently |
| Apr 1, 2016 | Canadian alert AL16-005 | A global victim total |
| Jan 10, 2018 | Microsoft page update date | A new 2018 origin for Locky |
Caption: Evidence grade: Confirmed dates; non-claims kept explicit.
Notes: Chronology and the "does not establish" column drawn from [1][2][3][4][5].

## PART 2 | Delivery, execution and impact are different stages

- A five-question model asks how material arrived, what executed, what components or services were involved, which data was reachable, and what proves safe resumption.
- The model is original to the study, not a claim about an invariant Locky sequence.
- Different teams may own each boundary, which is exactly why an incident can fall between responsibilities.
- A prevention report should name the stage it measured; a quarantined email is not proof an endpoint executed the payload.
Caption: Evidence grade: Original analytical model.
Notes: The five-stage model and the stage-naming discipline are the study's original analysis.

## PART 2 | Why the macro-only explanation fails

- Macros were important to early observations but not sufficient to describe the family.
- Microsoft's entry lists multiple downloader and exploit-kit routes as well as Office attachments.
- "Disable macros and the problem is solved" confuses a useful control with complete coverage.
- The right question is which execution paths remain after a policy change, and who is responsible for testing them safely.
Caption: Evidence grade: Reported family-entry observations plus original analysis.
Notes: Multiple routes from [5]; the control-versus-coverage point is original analysis.

## PART 2 | Distribution links need attribution discipline

- A shared sender pattern, overlapping infrastructure or a common downloader supports an investigative link, not an operator identity.
- Criminal services can be reused, rented or shared, so separate the family, the delivery cluster, the infrastructure owner and the responsible group.
- The bounded wording is that Proofpoint associated its Locky distribution with actor and botnet activity it had tracked around Dridex.
- The reporting names no responsible country and does not equate language artifacts with nationality.
Caption: Evidence grade: Reported association, not a criminal conviction.
Notes: Dridex-actor association and the attribution limits from [1]; keep affiliate structure distinct from one actor.

## PART 2 | Affected data is not the same as propagation

- An endpoint can damage data it has permission to modify without installing malware on the machine that stores that data.
- A shared folder's visible damage does not prove that every client using the folder is infected.
- These are different hypotheses needing different evidence; missing logs are a recorded limitation, not certainty.
- Broad write access can convert one compromised routine account into an organization-wide data problem.
Caption: Evidence grade: Original investigative analysis.
Notes: The affected-versus-propagation distinction and the permissions point are the study's original analysis.

## PART 2 | Encryption does not answer the exfiltration question

- The sources used here do not establish a universal Locky data-theft or double-extortion model.
- Absence of a theft allegation in these historical sources is not a forensic guarantee that nothing left any environment.
- Treat confidentiality and availability as separate investigative workstreams, each with its own evidence.
- A communications lead needs "not observed", "not yet assessed" and "ruled out within scope" kept distinct.
Caption: Evidence grade: Inferred guidance; no double-extortion model claimed.
Notes: No data-theft model appears in the sources used; the workstream guidance is original analysis.

## DEFENDER VIEW | Payment is not a recovery test

- Contemporary sources warned that payment did not guarantee restored access; the early investigators had not verified a decryptor after payment.
- Those observations justify caution; they do not quantify a universal probability of successful recovery.
- Prepare a decision process with authorized leadership and advisers, not an improvised response to an attacker's countdown.
- Even a working decryptor would not prove malware removal, restored account trust or completeness of recovered data.
Caption: Evidence grade: Confirmed warnings; no payment pathway tested.
Notes: Payment caveats from [1][4]; the decision-process framing is original analysis.

## DEFENDER VIEW | An evidence matrix for the investigation

The matrix turns an attractive narrative into questions that can be answered, challenged and updated.

| Question | Evidence to request | Important limitation |
|---|---|---|
| Was material delivered? | Message trace, attachment metadata, recipient report | Delivery does not prove execution |
| Did a device execute it? | Endpoint process history and alert context | Retention gaps prevent a firm conclusion |
| Which data was affected? | File-service logs, affected-file inventory, owner validation | Timestamps alone can be ambiguous |
| Were other devices involved? | Correlated endpoint and identity records | A common share is not common infection |
| Can the service be restored? | Isolated restore result and business acceptance test | Backup-job success is not acceptance |
Caption: Evidence grade: an original investigative aid.
Notes: Condensed from the study's evidence matrix; a product's Locky label guides investigation, it does not conclude it.

## CROSS-CUTTING THEMES | Where the record is overstated versus understated

Left: Easy to overstate
- One lure or one operator as the whole family.
- A single blocked attachment type as a solved problem.
- Payment, malware removal and restoration as one milestone.
Right: Easy to understate
- Adaptation across delivery, execution, reachable data and recovery.
- Separate owners and separate evidence at each boundary.
- A green backup job that has never passed a restore test.
Caption: Evidence grade: editorial corrections the case requires.
Notes: Keeps affected versus compromised and claimed versus confirmed distinct across [1] through [5].

## CLOSE | A connected system beats one memorized lure

- Delivery, execution, reachable data and recovery form a connected system with different owners and different evidence.
- A change in one part can invalidate an overly narrow defensive explanation.
- A backup that cannot be restored within a tolerable interruption is not a completed recovery capability.
- The response is disciplined scope, layered control ownership and demonstrated recovery, not exaggerated certainty.
Caption: Evidence grade: case-specific conclusion synthesis.
Notes: Conclusion synthesis across the study; rests on [1] through [5].
