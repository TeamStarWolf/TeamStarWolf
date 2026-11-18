# Slide plan: UCSF NetWalker 2020: A Payment Is Not a Recovery

- Study: case-studies/UCSF_NETWALKER_2020.md
- Cover title: UCSF NetWalker 2020 / A Payment Is Not a Recovery / Keeping affected distinct
- Subtitle: UCSF reported paying about $1.14 million in 2020; keeping encryption, data theft, payment and recovery as separate evidence-bounded claims.
- Published: 18 November 2026
- Notes: Conceptual study; no malware executed, no leaked records accessed, no attacker contacted.

## EXECUTIVE SUMMARY | A payment answers none of the recovery questions

- A ransomware incident at a research institution creates several distinct recovery questions.
- A ransom payment answers none of them by itself, even when it is made for a decryption tool.
- UCSF published multiple dated updates, so operational, payment and privacy claims can stay separate.
- The study separates institution-confirmed facts from NetWalker family context and original analysis.
Caption: Evidence grade: Confirmed disclosures; family attribution bounded.
Notes: Executive-assessment framing from [1][2][3]; no exploit code run and no attacker contacted.

## KEY FACTS | Three dated updates and one reported payment

Stat: Jun 1 | 2020 unauthorized access stopped
Stat: $1.14M | Reported payment for a tool
Stat: 3 | Dated UCSF updates in 2020
Stat: 21 | Proposed countermeasures, 2021
- Staff detected and stopped unauthorized access on June 1, 2020 in a limited School of Medicine environment.
- UCSF disclosed on June 26 a payment of about $1.14 million for a tool to unlock data and return obtained data.
- The consulted UCSF statements do not name the malware family; an Emsisoft profile associates it with NetWalker.
Caption: Evidence grade: Confirmed UCSF statements; NetWalker via vendor profile.
Notes: June 1 and scope from [1]; payment from [2]; family attribution layer from [8].

## WHAT UCSF DISCLOSED | Read the three 2020 updates together

Each public update answers a narrower question than a full forensic report would.

| Date | What UCSF stated | Does not establish |
|---|---|---|
| Jun 17, 2020 | Access stopped Jun 1; precautionary isolation; patient care unaffected | A verified recovery completion date |
| Jun 26, 2020 | About $1.14M paid; limited servers encrypted; academic work affected | That every obtained copy was deleted |
| Nov 6, 2020 | Notices on potentially affected personal information; no evidence of misuse | Confirmed misuse or a count of people |
Caption: Evidence grade: Confirmed, dated UCSF updates.
Notes: Sequence and the non-claims from [1][2][3]; the two-week return was kept as a forecast.

## PART 1 | Four meanings of the word affected

- A useful record separates malicious activity, precautionary isolation, business disruption and privacy risk.
- A server may be isolated for a trust relationship even when no malicious activity is confirmed on it.
- A workflow may be unavailable because a dependency was disconnected, not because its data was encrypted.
- Record confirmed encryption, confirmed access, precautionary isolation and unresolved status separately.
Caption: Evidence grade: Inferred; original classification discipline.
Notes: The four-meanings analysis is original, anchored to the scope UCSF itself stated in [1][2].

## PART 1 | Availability is not a privacy clearance

- A system that stays available can still hold information relevant to a confidentiality review.
- "Patient-care delivery unaffected" is a statement about operations, not about every record.
- It should not be rewritten as no health-related information was at risk without a separate finding.
- Keep affected versus compromised and claimed versus confirmed as distinct propositions.
Caption: Evidence grade: Inferred; bounded to UCSF's own wording.
Notes: The operations-versus-privacy distinction rests on [2][3]; the language discipline is original analysis.

## PART 2 | Payment and outcome should not be collapsed

- A payment is a transaction made under pressure, not a technical recovery result.
- Promised tool, delivered tool, decryption, validated data and restored operations are distinct milestones.
- Receiving a copy of obtained data does not establish that every other copy ceased to exist.
- A disclosed payment is not the full incident cost; if no total is published, leave the total unknown.
Caption: Evidence grade: Reported payment; outcome milestones kept separate.
Notes: The payment is stated and attributed to UCSF in [2]; the milestone discipline is original analysis.

## PART 2 | Discovery, disclosure and recovery are different clocks

- An incident timeline needs separate clocks: discovery, containment, disclosure and restoration.
- UCSF expected isolated systems back within about two weeks; that is a forecast, not a measurement.
- The consulted sources do not establish an exact recovery completion date, so none is asserted.
- Record the dependency behind each estimate so a date reflects the work that determines it.
Caption: Evidence grade: Confirmed forecast; completion date not in the record.
Notes: The two-week forecast is from [1]; the clock discipline and unknown completion are original analysis.

## PART 3 | Research data is more than readable files

- Restoring a subset that opens successfully may still leave a study unable to reproduce a finding.
- A folder's value depends on relationships among data, scripts, configuration and linkage records.
- A script from one date and a dataset from another can produce a plausible but incorrect combination.
- This is a defensive implication for research organizations, not a claim UCSF lost any dataset.
Caption: Evidence grade: Inferred; original research-recovery analysis.
Notes: The research-continuity reasoning is original; it makes no claim about UCSF's private data in [2].

## PART 3 | Backup coverage must be demonstrated

- A backup service existing is not proof a given workload was covered, retained and recoverable in time.
- Ask which assets are included, which excluded, who approved exclusions and when a restore was validated.
- Test whether a compromise of ordinary operational access can defeat the recovery option as well.
- Do not infer backups were absent from a payment, or adequate from a service existing somewhere.
Caption: Evidence grade: Inferred; original defensive analysis.
Notes: The backup-coverage discipline is original; the consulted disclosures give no backup architecture [2].

## RECOVERY WORKSHEET | A research worksheet, not UCSF's record

A proposed operational aid, not a record of UCSF's response; each row needs a named owner.

| Recovery question | Evidence or owner needed | Acceptance boundary |
|---|---|---|
| Which data is authoritative? | Research owner and provenance record | A convenient copy is not the source of record |
| Which versions belong together? | Dataset, code and configuration map | Readable files can be an invalid combination |
| Can outputs be reproduced? | Controlled representative rerun | Execution alone does not validate meaning |
| Are external dependencies available? | Tool, license and compute owners | A restored directory is not a working service |
Caption: Evidence grade: Original review tool.
Notes: Condensed from the study's research-recovery worksheet; a proposal, not UCSF's response.

## ATTRIBUTION | NetWalker context and its attribution boundary

Family and enforcement records give context, not UCSF-specific entry evidence.

| Date | Record | What it does not establish |
|---|---|---|
| Jul 28, 2020 | FBI NetWalker FLASH on access patterns | UCSF's specific entry point |
| Jan 27, 2021 | DOJ disruption; a defendant charged | That every infection had ended |
| Oct 4, 2022 | DOJ 20-year NetWalker sentence | That this person ran the UCSF intrusion |
| Family | Emsisoft profile placing UCSF | A substitute for UCSF forensic disclosure |
Caption: Evidence grade: Confirmed records; attribution boundary kept.
Notes: Context from [4][5][6][8]; no UCSF-specific attribution is inferred from any of them.

## GOVERNANCE | The review extended beyond the malware

- UCSF's 2021 IT Operating Model Task Force treated the incident as a catalyst for broader review.
- It identified problems in collaboration, capabilities, funding, accountability and security direction.
- It proposed twenty-one countermeasures across a multiyear program; recommendations are not implementation.
- Only the indexed executive summary was accessible; later passages redirected, so scope stays limited.
Caption: Evidence grade: Confirmed executive summary; implementation not audited.
Notes: The task-force summary, the twenty-one countermeasures and the retrieval limit are from [7].

## CROSS-CUTTING THEMES | What the retelling over- and understates

Left: Overstated in the usual retelling
- The payment headline read as the end of the incident.
- "Patient care unaffected" read as "no medical information at risk."
- A seizure beside the payment read as reimbursement.
Right: Understated and worth keeping
- A later personal-information notice covering several communities.
- Potential exposure, actual misuse and availability are different propositions.
- Governance conditions can outlast technical containment.
Caption: Evidence grade: editorial corrections the case requires.
Notes: Contrasts drawn from [2][3][5][7]; keep payment, data theft and recovery distinct.

## CLOSE | Precision beats a payment headline

- The case is more instructive when the payment is treated as one event, not the ending.
- UCSF's dated disclosures support a bounded operational account and a later privacy notification.
- Keep encryption, data theft, ransom paid and total cost as separate, sourced claims.
- Open gaps: no victim count, no verified completion date, no published total incident cost.
Caption: Evidence grade: case-specific conclusions, bounds preserved.
Notes: Conclusion synthesis across [1][2][3][7]; no certainty invented beyond the public record.
